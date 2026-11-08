//! The bus: subscribers, audience matching, fan-out, and the state replayed to new clients.
//!
//! Subscribers and the replay state sit behind one lock, so a client that says `hello` gets the
//! current state and then every later event, with nothing missed or doubled in between.

use std::sync::{Arc, Mutex};

use cleanroom_proto::{
    Audience, BusBody, BusMessage, Envelope, Frame, ScopeFlags, Signed, ToolDecision, ToolRequest,
    WIRE_VERSION,
};
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::lock;

/// Encoded lines waiting for one client's writer task.
pub(crate) type Outbox = mpsc::Sender<Arc<str>>;

/// One connected client.
#[derive(Debug)]
struct Subscriber {
    /// Registration number, for unsubscribing.
    id: u64,
    /// What it asked to receive.
    audiences: Vec<Audience>,
    /// Its writer queue.
    outbox: Outbox,
}

impl Subscriber {
    /// Messages to `all` reach everyone; anything else needs a matching audience.
    fn wants(&self, to: &Audience) -> bool {
        matches!(to, Audience::All) || self.audiences.contains(to)
    }
}

/// Subscribers plus replay state.
#[derive(Debug, Default)]
pub(crate) struct Bus {
    /// Everything behind the one lock.
    inner: Mutex<Inner>,
}

/// The locked part of [`Bus`].
#[derive(Debug, Default)]
struct Inner {
    /// Connected clients.
    subscribers: Vec<Subscriber>,
    /// What a new client is told first.
    replay: Replay,
    /// Next registration number.
    next_id: u64,
}

/// Something a commander can decide.
#[derive(Debug)]
pub(crate) enum Subject {
    /// A pending tool request.
    Tool(ToolRequest),
    /// A containment proposal.
    Proposal {
        /// What it proposes.
        action: String,
    },
}

impl Bus {
    /// Register a client and queue the current state for it.
    pub(crate) fn subscribe(&self, audiences: Vec<Audience>, outbox: Outbox) -> u64 {
        let mut inner = lock(&self.inner);
        let id = inner.next_id;
        inner.next_id += 1;
        let subscriber = Subscriber {
            id,
            audiences,
            outbox,
        };
        for message in inner.replay.snapshot() {
            if !subscriber.wants(&message.body.to) {
                continue;
            }
            if let Some(line) = encode(message.clone())
                && subscriber.outbox.try_send(line).is_err()
            {
                tracing::warn!(id, "a new client cannot take the replayed state");
                break;
            }
        }
        inner.subscribers.push(subscriber);
        id
    }

    /// Forget a client.
    pub(crate) fn unsubscribe(&self, id: u64) {
        lock(&self.inner)
            .subscribers
            .retain(|subscriber| subscriber.id != id);
    }

    /// Fold `message` into the replay state and deliver it to every matching client, the
    /// sender included. A client whose queue is full is dropped from the bus.
    pub(crate) fn fan_out(&self, message: Signed<BusMessage>) {
        let mut inner = lock(&self.inner);
        inner.replay.observe(&message);
        let to = message.body.to.clone();
        let Some(line) = encode(message) else {
            return;
        };
        inner.subscribers.retain(|subscriber| {
            if !subscriber.wants(&to) {
                return true;
            }
            match subscriber.outbox.try_send(Arc::clone(&line)) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    tracing::warn!(
                        id = subscriber.id,
                        "client is not reading its events; dropping it from the bus"
                    );
                    false
                }
                Err(TrySendError::Closed(_)) => false,
            }
        });
    }

    /// Remove an open tool request or proposal so exactly one decision applies to it.
    pub(crate) fn take_subject(&self, id: &str) -> Option<Subject> {
        lock(&self.inner).replay.take_subject(id)
    }

    /// Id of the latest incident record on the bus.
    pub(crate) fn incident_id(&self) -> Option<String> {
        lock(&self.inner).replay.incident_id()
    }

    /// Flags of the latest scope record on the bus for `asset_id`.
    pub(crate) fn scope_flags(&self, asset_id: &str) -> Option<ScopeFlags> {
        let inner = lock(&self.inner);
        inner
            .replay
            .scopes
            .iter()
            .find(|(id, _)| id == asset_id)
            .and_then(|(_, message)| {
                if let BusBody::Scope(record) = &message.body.body {
                    Some(record.flags)
                } else {
                    None
                }
            })
    }

    /// Forget the incident, its scope records, and its open requests and proposals (reset).
    pub(crate) fn clear_incident(&self) {
        lock(&self.inner).replay.clear_incident();
    }
}

/// One `event` line.
fn encode(message: Signed<BusMessage>) -> Option<Arc<str>> {
    let envelope = Envelope {
        v: WIRE_VERSION,
        frame: Frame::Event(message),
    };
    match serde_json::to_string(&envelope) {
        Ok(mut line) => {
            line.push('\n');
            Some(line.into())
        }
        Err(error) => {
            tracing::error!("cannot encode an event: {error}");
            None
        }
    }
}

/// The state a client gets right after `hello`: the latest incident, the latest scope per
/// asset, open tool requests and proposals, and the latest counters.
#[derive(Debug, Default)]
pub(crate) struct Replay {
    /// Latest `incident`.
    incident: Option<Signed<BusMessage>>,
    /// Latest `scope` per asset id, in first-seen order.
    scopes: Vec<(String, Signed<BusMessage>)>,
    /// `tool_request`s without a final decision, by request id.
    tool_requests: Vec<(String, Signed<BusMessage>)>,
    /// `proposal`s without a commander decision, by proposal id.
    proposals: Vec<(String, Signed<BusMessage>)>,
    /// Latest `counters`.
    counters: Option<Signed<BusMessage>>,
    /// Latest `memory` map per role, in first-seen order.
    memory: Vec<(String, Signed<BusMessage>)>,
}

impl Replay {
    /// Fold one fanned-out message into the state.
    pub(crate) fn observe(&mut self, message: &Signed<BusMessage>) {
        match &message.body.body {
            BusBody::Incident(_) => self.incident = Some(message.clone()),
            BusBody::Scope(record) => upsert(&mut self.scopes, &record.asset_id, message),
            BusBody::ToolRequest(request) => {
                upsert(&mut self.tool_requests, &request.id, message);
            }
            BusBody::ToolDecision {
                request_id,
                decision,
            } => {
                if !matches!(decision, ToolDecision::Pending) {
                    remove(&mut self.tool_requests, request_id);
                }
            }
            BusBody::Proposal { proposal_id, .. } => {
                upsert(&mut self.proposals, proposal_id, message);
            }
            BusBody::Approval { subject_id, .. } => {
                remove(&mut self.proposals, subject_id);
                remove(&mut self.tool_requests, subject_id);
            }
            BusBody::Counters { .. } => self.counters = Some(message.clone()),
            BusBody::Memory(map) => upsert(&mut self.memory, &format!("{:?}", map.role), message),
            BusBody::Chat { .. }
            | BusBody::Finding { .. }
            | BusBody::Trace { .. }
            | BusBody::Refusal { .. }
            | BusBody::SafetyVerdict { .. }
            | BusBody::Route { .. }
            | BusBody::Status { .. }
            | BusBody::Investigate { .. }
            | BusBody::AgentControl { .. } => {}
        }
    }

    /// The messages to replay, in the documented order.
    pub(crate) fn snapshot(&self) -> impl Iterator<Item = &Signed<BusMessage>> {
        self.incident
            .iter()
            .chain(self.scopes.iter().map(|(_, message)| message))
            .chain(self.tool_requests.iter().map(|(_, message)| message))
            .chain(self.proposals.iter().map(|(_, message)| message))
            .chain(self.counters.iter())
            .chain(self.memory.iter().map(|(_, message)| message))
    }

    /// Remove an open subject by id.
    fn take_subject(&mut self, id: &str) -> Option<Subject> {
        if let Some(message) = remove(&mut self.proposals, id)
            && let BusBody::Proposal { action, .. } = message.body.body
        {
            return Some(Subject::Proposal { action });
        }
        if let Some(message) = remove(&mut self.tool_requests, id)
            && let BusBody::ToolRequest(request) = message.body.body
        {
            return Some(Subject::Tool(request));
        }
        None
    }

    /// Id of the latest incident record.
    fn incident_id(&self) -> Option<String> {
        match &self.incident.as_ref()?.body.body {
            BusBody::Incident(record) => Some(record.id.clone()),
            BusBody::Chat { .. }
            | BusBody::Finding { .. }
            | BusBody::Proposal { .. }
            | BusBody::Approval { .. }
            | BusBody::ToolRequest(_)
            | BusBody::ToolDecision { .. }
            | BusBody::Trace { .. }
            | BusBody::Refusal { .. }
            | BusBody::Counters { .. }
            | BusBody::SafetyVerdict { .. }
            | BusBody::Route { .. }
            | BusBody::Scope(_)
            | BusBody::Status { .. }
            | BusBody::Investigate { .. }
            | BusBody::AgentControl { .. }
            | BusBody::Memory(_) => None,
        }
    }

    /// Forget everything but the counters, which belong to the agent runner.
    fn clear_incident(&mut self) {
        self.incident = None;
        self.scopes.clear();
        self.tool_requests.clear();
        self.proposals.clear();
        self.memory.clear();
    }
}

/// Replace the entry for `key`, or append it.
fn upsert(
    entries: &mut Vec<(String, Signed<BusMessage>)>,
    key: &str,
    message: &Signed<BusMessage>,
) {
    match entries.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, slot)) => *slot = message.clone(),
        None => entries.push((key.to_owned(), message.clone())),
    }
}

/// Remove and return the entry for `key`.
fn remove(
    entries: &mut Vec<(String, Signed<BusMessage>)>,
    key: &str,
) -> Option<Signed<BusMessage>> {
    let index = entries.iter().position(|(existing, _)| existing == key)?;
    Some(entries.remove(index).1)
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{
        IncidentRecord, IncidentStatus, LlmMode, Principal, Role, ScopeFlags, ScopeRecord,
        Severity, ToolSource, Tri, Triggers,
    };

    use super::*;

    fn message(id: &str, body: BusBody) -> Signed<BusMessage> {
        Signed {
            domain: cleanroom_proto::domain::BUS.into(),
            body: BusMessage {
                id: id.into(),
                at: "2026-11-08T02:00:00Z".into(),
                from: Principal::System,
                to: Audience::All,
                body,
            },
            signer: "sha256:test".into(),
            sig: String::new(),
        }
    }

    fn scope(asset_id: &str, locked: Tri) -> BusBody {
        BusBody::Scope(ScopeRecord {
            asset_id: asset_id.into(),
            name: asset_id.into(),
            data_classes: Vec::new(),
            record_count: 1,
            texas_residents: 0,
            flags: ScopeFlags {
                locked,
                ..ScopeFlags::default()
            },
            encrypted_at_rest: false,
            key_exposed: Tri::No,
            confidence_pct: 100,
            evidence: Vec::new(),
            updated_by: Principal::System,
            updated_at: "2026-11-08T02:00:00Z".into(),
        })
    }

    fn incident(status: IncidentStatus) -> BusBody {
        BusBody::Incident(IncidentRecord {
            id: "INC-1".into(),
            title: "Ransomware on acme-fs".into(),
            status,
            severity: Severity::High,
            category: "ransomware".into(),
            detected_at: "2026-11-08T02:00:00Z".into(),
            reported_by: Principal::System,
            summary: "share encrypted".into(),
            affected_systems: vec!["acme-fs".into()],
            triggers: Triggers::default(),
            timeline: Vec::new(),
        })
    }

    fn tool_request(id: &str) -> BusBody {
        BusBody::ToolRequest(ToolRequest {
            id: id.into(),
            from: Role::Forensics,
            stratum: "forensics".into(),
            tool: "volatility3".into(),
            source: ToolSource::Nix {
                flake_ref: "github:NixOS/nixpkgs/rev#volatility3".into(),
            },
            reason: "memory image".into(),
        })
    }

    fn proposal(id: &str) -> BusBody {
        BusBody::Proposal {
            proposal_id: id.into(),
            action: "isolate acme-fs".into(),
            rationale: "ransomware".into(),
        }
    }

    fn counters(blocked_by_os: u32) -> BusBody {
        BusBody::Counters {
            blocked_by_model: 0,
            blocked_by_os,
            safety_flags: 0,
            guardrails: true,
            llm: LlmMode::Live,
        }
    }

    #[test]
    fn replay_keeps_latest_records_and_open_subjects_only() {
        let mut replay = Replay::default();
        let events = [
            message("m1", scope("payroll", Tri::No)),
            message("m2", scope("contracts", Tri::No)),
            message("m3", incident(IncidentStatus::Detected)),
            message("m4", scope("payroll", Tri::Yes)),
            message("m5", BusBody::Chat { text: "hi".into() }),
            message("m6", tool_request("t1")),
            message("m7", tool_request("t2")),
            message(
                "m8",
                BusBody::ToolDecision {
                    request_id: "t2".into(),
                    decision: ToolDecision::AutoAllowed {
                        rule: "allowlist".into(),
                    },
                },
            ),
            message(
                "m9",
                BusBody::ToolDecision {
                    request_id: "t1".into(),
                    decision: ToolDecision::Pending,
                },
            ),
            message("m10", proposal("p1")),
            message("m11", proposal("p2")),
            message(
                "m12",
                BusBody::Approval {
                    subject_id: "p1".into(),
                    approved: true,
                },
            ),
            message("m13", counters(0)),
            message("m14", incident(IncidentStatus::Analyzing)),
            message("m15", counters(1)),
        ];
        for event in &events {
            replay.observe(event);
        }
        let ids: Vec<&str> = replay
            .snapshot()
            .map(|message| message.body.id.as_str())
            .collect();
        assert_eq!(
            ids,
            ["m14", "m4", "m2", "m6", "m11", "m15"],
            "latest incident, latest scope per asset in first-seen order, open tool request, \
             open proposal, latest counters"
        );
    }

    #[test]
    fn taking_a_subject_closes_it_and_reset_keeps_counters() {
        let mut replay = Replay::default();
        for event in [
            message("m1", tool_request("t1")),
            message("m2", proposal("p1")),
            message("m3", counters(2)),
            message("m4", incident(IncidentStatus::Detected)),
        ] {
            replay.observe(&event);
        }
        assert!(
            matches!(replay.take_subject("p1"), Some(Subject::Proposal { .. })),
            "the proposal is open"
        );
        assert!(
            replay.take_subject("p1").is_none(),
            "a second decision finds nothing"
        );
        assert!(
            matches!(replay.take_subject("t1"), Some(Subject::Tool(request)) if request.tool == "volatility3"),
            "the tool request is open"
        );
        assert_eq!(
            replay.incident_id().as_deref(),
            Some("INC-1"),
            "incident id"
        );
        replay.clear_incident();
        let ids: Vec<&str> = replay
            .snapshot()
            .map(|message| message.body.id.as_str())
            .collect();
        assert_eq!(ids, ["m3"], "only the counters survive a reset");
    }
}
