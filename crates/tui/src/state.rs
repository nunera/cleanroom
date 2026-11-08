//! The reducer: folds daemon frames into everything the command center shows.
//!
//! [`State::apply`] is the only way state changes from the outside. Live mode, replay mode and
//! offline renders all feed it the same [`Envelope`]s, so the screen depends on daemon frames
//! alone.

use std::collections::{HashSet, VecDeque};

use cleanroom_proto::{
    BusBody, BusMessage, CoreResponse, Envelope, ExecResult, Frame, IncidentRecord, IncidentStatus,
    KeyId, ModelRoute, Principal, Role, ScopeRecord, ToolDecision, ToolRequest, ToolSource, Tri,
    Triggers, WIRE_VERSION,
};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::Value;

/// Agent-pane lines kept in memory.
const ACTIVITY_LIMIT: usize = 500;
/// Chat lines kept in memory.
const CHAT_LIMIT: usize = 200;
/// Longest text kept from a single trace argument or result.
const PREVIEW_CHARS: usize = 160;

/// What the console asked `cleanroomd` for, so its response can be explained.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SentRequest {
    /// `detonate` a scenario.
    Detonate {
        /// Scenario name.
        scenario: String,
    },
    /// `tamper` with a root (demo opener).
    Tamper {
        /// Root name.
        root: String,
    },
    /// `admit` a root again after tampering.
    Admit {
        /// Root name.
        root: String,
    },
    /// `approve` with a signed decision.
    Decide {
        /// Tool request or proposal id.
        subject_id: String,
        /// Approve (true) or deny (false).
        approved: bool,
    },
    /// `verify_log`.
    VerifyLog,
    /// `reset`.
    Reset,
}

impl SentRequest {
    /// Human wording for notices.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Detonate { scenario } => format!("Detonate {scenario}"),
            Self::Tamper { root } => format!("Tamper with {root}"),
            Self::Admit { root } => format!("Admit {root}"),
            Self::Decide {
                subject_id,
                approved: true,
            } => format!("Approve {subject_id}"),
            Self::Decide {
                subject_id,
                approved: false,
            } => format!("Deny {subject_id}"),
            Self::VerifyLog => "Verify log".to_owned(),
            Self::Reset => "Reset".to_owned(),
        }
    }
}

/// Emphasis of a line or notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Background detail.
    Quiet,
    /// Ordinary activity.
    Plain,
    /// Something went right.
    Good,
    /// Needs attention.
    Warn,
    /// Blocked, failed or compromised.
    Bad,
}

/// Who sent a bus message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Who {
    /// An agent role.
    Agent(Role),
    /// `cleanroomd` itself.
    System,
    /// This console's commander key.
    Me,
    /// Another human, by short key id.
    Human(String),
}

/// One line in the live agent pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Activity {
    /// Local `HH:MM:SS`.
    pub(crate) at: String,
    /// Sender.
    pub(crate) who: Who,
    /// Short kind label, for example `TRACE` or `BLOCKED BY OS`.
    pub(crate) tag: &'static str,
    /// Emphasis.
    pub(crate) tone: Tone,
    /// The line itself.
    pub(crate) text: String,
}

/// One chat line in the comms pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatLine {
    /// Local `HH:MM:SS`.
    pub(crate) at: String,
    /// Sender.
    pub(crate) who: Who,
    /// Message text.
    pub(crate) text: String,
}

/// What a queued item asks the commander to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ask {
    /// An agent wants a tool it doesn't have.
    Tool {
        /// Tool name.
        tool: String,
        /// Pinned source, as text.
        source: String,
        /// The agent's stated reason.
        reason: String,
    },
    /// Containment proposes an action.
    Proposal {
        /// What would be done.
        action: String,
        /// Why.
        rationale: String,
    },
}

/// One item in the approvals queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueueItem {
    /// Tool request id or proposal id: the approval's subject.
    pub(crate) subject_id: String,
    /// Who asked.
    pub(crate) from: Who,
    /// What they asked for.
    pub(crate) ask: Ask,
    /// The commander's decision once `cleanroomd` accepted it, until the bus confirms it.
    pub(crate) sent: Option<bool>,
}

/// Team-wide counters the agent runtime publishes in `status` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Counters {
    /// Injected instructions stopped by the model layer while guardrails were on.
    pub(crate) blocked_by_model: u32,
    /// Actions the kernel grant denied.
    pub(crate) blocked_by_os: u32,
    /// Every unsafe safety verdict, guardrails on or off.
    pub(crate) safety_flags: u32,
    /// Where model calls come from: `live`, `record` or `replay`.
    pub(crate) llm: Option<String>,
}

/// Result of the last `verify_log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogStatus {
    /// Not verified in this session.
    Unverified,
    /// The chain is intact.
    Intact {
        /// Receipts checked.
        entries: u64,
    },
    /// The chain breaks.
    Broken {
        /// Receipts checked.
        entries: u64,
        /// First receipt whose `prev` doesn't match.
        first_break: u64,
    },
}

/// Result of the last `admit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The root's bytes match its lock.
    Admitted {
        /// Root name.
        root: String,
        /// Manifest digest.
        manifest: String,
    },
    /// The root was refused.
    Rejected {
        /// Root name.
        root: String,
        /// First layer whose bytes don't match.
        layer: String,
        /// Digest the lock expects.
        expected: String,
        /// Digest actually found.
        actual: String,
    },
}

/// A one-line status message for the commander.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    /// Emphasis.
    pub(crate) tone: Tone,
    /// Message.
    pub(crate) text: String,
}

/// When and from whom a bus message came, as displayed.
#[derive(Debug, Clone)]
struct Origin {
    /// Local `HH:MM:SS`.
    at: String,
    /// Sender.
    who: Who,
}

/// What one agent-pane line says, before it is stamped with an [`Origin`].
#[derive(Debug)]
struct Entry {
    /// Kind label.
    tag: &'static str,
    /// Emphasis.
    tone: Tone,
    /// The line itself.
    text: String,
}

impl Entry {
    /// An entry tagged `tag`.
    const fn new(tag: &'static str, tone: Tone, text: String) -> Self {
        Self { tag, tone, text }
    }
}

/// Everything the command center shows, built only from daemon frames.
#[derive(Debug)]
pub struct State {
    /// Zone for displayed times.
    pub(crate) display_tz: TimeZone,
    /// This console's key id, to label its own messages.
    pub(crate) me: Option<KeyId>,
    /// The incident record, once declared.
    pub(crate) incident: Option<IncidentRecord>,
    /// One record per asset, in first-seen order.
    pub(crate) scope: Vec<ScopeRecord>,
    /// Live agent pane, oldest first.
    pub(crate) activity: VecDeque<Activity>,
    /// Human chat, oldest first.
    pub(crate) chat: VecDeque<ChatLine>,
    /// Pending tool requests and proposals.
    pub(crate) queue: Vec<QueueItem>,
    /// Subjects already decided, so a late request doesn't re-enter the queue.
    pub(crate) decided: HashSet<String>,
    /// Hardened agent prompts (true) or the naive prompt (false).
    pub(crate) guardrails: bool,
    /// Latest counters from the agent runtime.
    pub(crate) counters: Option<Counters>,
    /// Receipt log verification.
    pub(crate) log: LogStatus,
    /// Latest admission result.
    pub(crate) admission: Option<Admission>,
    /// Bumped on every admission result, so the overlay can be dismissed per result.
    pub(crate) admission_seq: u64,
    /// Incident the agent team was last started on.
    pub(crate) investigating: Option<String>,
    /// Latest notice.
    pub(crate) notice: Option<Notice>,
}

impl State {
    /// Empty state that displays times in `display_tz`.
    #[must_use]
    pub fn new(display_tz: TimeZone) -> Self {
        Self {
            display_tz,
            me: None,
            incident: None,
            scope: Vec::new(),
            activity: VecDeque::new(),
            chat: VecDeque::new(),
            queue: Vec::new(),
            decided: HashSet::new(),
            guardrails: true,
            counters: None,
            log: LogStatus::Unverified,
            admission: None,
            admission_seq: 0,
            investigating: None,
            notice: None,
        }
    }

    /// Label messages signed by `key_id` as this console's own.
    pub(crate) fn set_identity(&mut self, key_id: KeyId) {
        self.me = Some(key_id);
    }

    /// Fold one frame from `cleanroomd` into the state.
    ///
    /// `request` is what this console sent under a `response` frame's id, when known; replays
    /// and offline renders pass `None`. `now` stamps lines that come from responses, which
    /// carry no time of their own.
    pub fn apply(&mut self, envelope: Envelope, request: Option<&SentRequest>, now: Timestamp) {
        if envelope.v != WIRE_VERSION {
            self.notify(
                Tone::Warn,
                format!("Ignored a frame with wire version {}", envelope.v),
            );
            return;
        }
        match envelope.frame {
            Frame::Event(signed) => self.apply_message(signed.body),
            Frame::Response { response, .. } => self.apply_response(response, request, now),
            Frame::Hello { .. } | Frame::Publish(_) | Frame::Request { .. } => {
                self.notify(Tone::Warn, "Ignored a client-only frame from cleanroomd");
            }
        }
    }

    /// Replace the latest notice.
    pub(crate) fn notify(&mut self, tone: Tone, text: impl Into<String>) {
        self.notice = Some(Notice {
            tone,
            text: text.into(),
        });
    }

    /// Queue items still waiting for the commander's signature.
    pub(crate) fn waiting(&self) -> usize {
        self.queue.iter().filter(|item| item.sent.is_none()).count()
    }

    /// Incident triggers, or none before an incident exists.
    pub(crate) fn triggers(&self) -> Triggers {
        self.incident
            .as_ref()
            .map(|incident| incident.triggers.clone())
            .unwrap_or_default()
    }

    /// `HH:MM:SS` in the display zone, or the raw text when it isn't a timestamp.
    pub(crate) fn time_label(&self, at: &str) -> String {
        at.parse::<Timestamp>()
            .map_or_else(|_| at.to_owned(), |stamp| self.stamp_label(stamp))
    }

    /// Classify a principal for display.
    pub(crate) fn who(&self, principal: &Principal) -> Who {
        match principal {
            Principal::Agent { role } => Who::Agent(*role),
            Principal::System => Who::System,
            Principal::Human { key_id } if self.me.as_ref() == Some(key_id) => Who::Me,
            Principal::Human { key_id } => Who::Human(short_key(key_id)),
        }
    }

    /// Apply a bus message.
    fn apply_message(&mut self, message: BusMessage) {
        let origin = Origin {
            at: self.time_label(&message.at),
            who: self.who(&message.from),
        };
        match message.body {
            BusBody::Chat { text } => {
                let Origin { at, who } = origin;
                push_capped(&mut self.chat, ChatLine { at, who, text }, CHAT_LIMIT);
            }
            BusBody::Finding {
                summary,
                evidence,
                confidence_pct,
            } => self.log(
                &origin,
                finding_entry(&summary, evidence.len(), confidence_pct),
            ),
            BusBody::Proposal {
                proposal_id,
                action,
                rationale,
            } => {
                let entry = Entry::new("PROPOSAL", Tone::Warn, format!("{action}: {rationale}"));
                let ask = Ask::Proposal { action, rationale };
                self.enqueue(proposal_id, origin.who.clone(), ask);
                self.log(&origin, entry);
            }
            BusBody::Approval {
                subject_id,
                approved,
            } => {
                self.settle(&subject_id);
                self.log(&origin, approval_entry(subject_id, approved));
            }
            BusBody::ToolRequest(request) => self.tool_request(&origin, request),
            BusBody::ToolDecision {
                request_id,
                decision,
            } => self.tool_decision(&origin, &request_id, decision),
            BusBody::Trace {
                step,
                tool,
                args,
                result_preview,
            } => self.log(&origin, trace_entry(step, &tool, &args, &result_preview)),
            BusBody::SafetyVerdict {
                artifact,
                model,
                safe,
                categories,
            } => self.log(&origin, safety_entry(&artifact, &model, safe, &categories)),
            BusBody::Route { route, reason } => self.log(&origin, route_entry(route, &reason)),
            BusBody::Scope(record) => self.scope_update(&origin, record),
            BusBody::Incident(record) => self.incident_update(&origin, record),
            BusBody::Status { text } => self.status(&origin, text),
            BusBody::Investigate { incident_id, brief } => {
                let text = format!("{incident_id}: {brief}");
                self.log(&origin, Entry::new("INVESTIGATE", Tone::Plain, text));
                self.investigating = Some(incident_id);
            }
            BusBody::AgentControl { guardrails } => {
                self.guardrails = guardrails;
                self.log(&origin, guardrails_entry(guardrails));
            }
        }
    }

    /// Apply the daemon's answer to one of this console's requests.
    fn apply_response(
        &mut self,
        response: CoreResponse,
        request: Option<&SentRequest>,
        now: Timestamp,
    ) {
        match response {
            CoreResponse::Ok => self.ok(request),
            CoreResponse::Error { message } => {
                if let Some(SentRequest::Decide { subject_id, .. }) = request {
                    self.mark_sent(subject_id, None);
                }
                let what = request.map_or_else(|| "Request".to_owned(), SentRequest::describe);
                self.notify(Tone::Bad, format!("{what} failed: {message}"));
            }
            CoreResponse::AdmitRejected {
                root,
                layer,
                expected,
                actual,
            } => {
                let text = format!("{root} refused: layer {layer} does not match its lock");
                self.log(
                    &self.system_origin(now),
                    Entry::new("ADMISSION", Tone::Bad, text.clone()),
                );
                self.notify(Tone::Bad, text);
                self.set_admission(Admission::Rejected {
                    root,
                    layer,
                    expected,
                    actual,
                });
            }
            CoreResponse::Admitted { root, manifest } => {
                let text = format!("{root} admitted: {manifest}");
                self.log(
                    &self.system_origin(now),
                    Entry::new("ADMISSION", Tone::Good, text.clone()),
                );
                self.notify(Tone::Good, text);
                self.set_admission(Admission::Admitted { root, manifest });
            }
            CoreResponse::LogVerified {
                entries,
                first_break,
            } => self.log_verified(entries, first_break),
            CoreResponse::Tool {
                request_id,
                decision,
            } => self.tool_decision(&self.system_origin(now), &request_id, decision),
            CoreResponse::Exec(ExecResult { receipt_seq, .. }) => self.notify(
                Tone::Quiet,
                format!("Ignored an exec result (receipt {receipt_seq}) meant for an agent runner"),
            ),
        }
    }

    /// An `ok` response.
    fn ok(&mut self, request: Option<&SentRequest>) {
        match request {
            Some(SentRequest::Reset) => {
                self.clear();
                self.notify(Tone::Good, "Reset done. The console starts fresh.");
            }
            Some(SentRequest::Detonate { scenario }) => self.notify(
                Tone::Warn,
                format!("Detonated {scenario} in the sacrificial stratum. Watch the scope table."),
            ),
            Some(SentRequest::Tamper { root }) => self.notify(
                Tone::Warn,
                format!("Flipped a byte in {root}. Re-admitting it now…"),
            ),
            Some(SentRequest::Decide {
                subject_id,
                approved,
            }) => {
                self.mark_sent(subject_id, Some(*approved));
                let verb = if *approved { "Approval" } else { "Denial" };
                self.notify(
                    Tone::Good,
                    format!("{verb} of {subject_id} signed and accepted by cleanroomd."),
                );
            }
            Some(request @ (SentRequest::Admit { .. } | SentRequest::VerifyLog)) => {
                self.notify(Tone::Plain, format!("{}: ok", request.describe()));
            }
            None => self.notify(Tone::Plain, "cleanroomd: ok"),
        }
    }

    /// Record a new admission result.
    fn set_admission(&mut self, admission: Admission) {
        self.admission = Some(admission);
        self.admission_seq = self.admission_seq.saturating_add(1);
    }

    /// A `log_verified` response.
    fn log_verified(&mut self, entries: u64, first_break: Option<u64>) {
        if let Some(first_break) = first_break {
            self.log = LogStatus::Broken {
                entries,
                first_break,
            };
            self.notify(
                Tone::Bad,
                format!("Receipt log BROKEN at entry {first_break} of {entries}."),
            );
        } else {
            self.log = LogStatus::Intact { entries };
            self.notify(
                Tone::Good,
                format!("Receipt log verified: {entries} receipts, chain intact."),
            );
        }
    }

    /// Forget everything about the previous run. Guardrails and identity survive: they belong to
    /// the agents and this console, not to the incident.
    fn clear(&mut self) {
        self.incident = None;
        self.scope.clear();
        self.activity.clear();
        self.chat.clear();
        self.queue.clear();
        self.decided.clear();
        self.counters = None;
        self.log = LogStatus::Unverified;
        self.admission = None;
        self.investigating = None;
    }

    /// A `tool_request` message.
    fn tool_request(&mut self, origin: &Origin, request: ToolRequest) {
        let ToolRequest {
            id,
            tool,
            source,
            reason,
            ..
        } = request;
        let source = match source {
            ToolSource::Nix { flake_ref } => format!("nix {flake_ref}"),
            ToolSource::Oci { image, manifest } => format!("oci {image}@{manifest}"),
        };
        let text = format!("needs {tool} ({source}): {reason}");
        let ask = Ask::Tool {
            tool,
            source,
            reason,
        };
        self.enqueue(id, origin.who.clone(), ask);
        self.log(origin, Entry::new("TOOL REQUEST", Tone::Warn, text));
    }

    /// A `tool_decision` message or `tool` response. Anything but `pending` settles the request.
    fn tool_decision(&mut self, origin: &Origin, request_id: &str, decision: ToolDecision) {
        let (tone, text) = match decision {
            ToolDecision::Pending => (
                Tone::Warn,
                format!("{request_id} is outside policy: waiting for your signature"),
            ),
            ToolDecision::AutoAllowed { rule } => (
                Tone::Good,
                format!("{request_id} auto-allowed by rule {rule}"),
            ),
            ToolDecision::Approved { approver } => (
                Tone::Good,
                format!("{request_id} approved by {}", short_key(&approver)),
            ),
            ToolDecision::Denied { reason } => {
                (Tone::Bad, format!("{request_id} denied: {reason}"))
            }
        };
        if tone != Tone::Warn {
            self.settle(request_id);
        }
        self.log(origin, Entry::new("TOOL", tone, text));
    }

    /// A full scope record for one asset. Logs a line when its flags change.
    fn scope_update(&mut self, origin: &Origin, record: ScopeRecord) {
        let index = self
            .scope
            .iter()
            .position(|asset| asset.asset_id == record.asset_id);
        let changed = index
            .and_then(|index| self.scope.get(index))
            .is_none_or(|old| old.flags != record.flags);
        if changed {
            self.log(origin, scope_entry(&record));
        }
        match index.and_then(|index| self.scope.get_mut(index)) {
            Some(slot) => *slot = record,
            None => self.scope.push(record),
        }
    }

    /// A full incident record. Logs declarations, status changes and newly started clocks.
    fn incident_update(&mut self, origin: &Origin, record: IncidentRecord) {
        let previous = self.incident.take();
        let status = status_word(record.status);
        match &previous {
            Some(old) if old.id == record.id => {
                if old.status != record.status {
                    let text = format!("{} is now {status}", record.id);
                    self.log(origin, Entry::new("INCIDENT", Tone::Warn, text));
                }
            }
            Some(_) | None => {
                let text = format!("{} declared: {} ({status})", record.id, record.title);
                self.log(origin, Entry::new("INCIDENT", Tone::Bad, text));
            }
        }
        let old_triggers = previous.map(|old| old.triggers).unwrap_or_default();
        for name in started_clocks(&old_triggers, &record.triggers) {
            let text = format!("{name} clock started");
            self.log(origin, Entry::new("LEGAL CLOCK", Tone::Warn, text));
        }
        self.incident = Some(record);
    }

    /// A `status` message: agent-runtime counters, or plain status text.
    fn status(&mut self, origin: &Origin, text: String) {
        if let Some((counters, guardrails)) = parse_counters(&text) {
            self.counters = Some(counters);
            if let Some(guardrails) = guardrails {
                self.guardrails = guardrails;
            }
        } else {
            self.log(origin, Entry::new("STATUS", Tone::Plain, text));
        }
    }

    /// Add an approval subject unless it is already queued or decided.
    fn enqueue(&mut self, subject_id: String, from: Who, ask: Ask) {
        let known = self.decided.contains(&subject_id)
            || self.queue.iter().any(|item| item.subject_id == subject_id);
        if !known {
            self.queue.push(QueueItem {
                subject_id,
                from,
                ask,
                sent: None,
            });
        }
    }

    /// A subject was decided on the bus: drop it from the queue for good.
    fn settle(&mut self, subject_id: &str) {
        self.queue.retain(|item| item.subject_id != subject_id);
        self.decided.insert(subject_id.to_owned());
    }

    /// Record (or clear) the decision cleanroomd accepted for a queued subject.
    fn mark_sent(&mut self, subject_id: &str, decision: Option<bool>) {
        if let Some(item) = self
            .queue
            .iter_mut()
            .find(|item| item.subject_id == subject_id)
        {
            item.sent = decision;
        }
    }

    /// Append to the agent pane.
    fn log(&mut self, origin: &Origin, entry: Entry) {
        let activity = Activity {
            at: origin.at.clone(),
            who: origin.who.clone(),
            tag: entry.tag,
            tone: entry.tone,
            text: entry.text,
        };
        push_capped(&mut self.activity, activity, ACTIVITY_LIMIT);
    }

    /// `cleanroomd` at `now`: the origin of response-driven lines.
    fn system_origin(&self, now: Timestamp) -> Origin {
        Origin {
            at: self.stamp_label(now),
            who: Who::System,
        }
    }

    /// `HH:MM:SS` of `stamp` in the display zone.
    fn stamp_label(&self, stamp: Timestamp) -> String {
        let time = stamp.to_zoned(self.display_tz.clone()).time();
        format!(
            "{:02}:{:02}:{:02}",
            time.hour(),
            time.minute(),
            time.second()
        )
    }
}

/// Push to a bounded log, dropping the oldest entry when full.
fn push_capped<T>(log: &mut VecDeque<T>, item: T, limit: usize) {
    if log.len() >= limit {
        log.pop_front();
    }
    log.push_back(item);
}

/// First 8 hex digits of a key id.
pub(crate) fn short_key(key_id: &str) -> String {
    key_id
        .strip_prefix("sha256:")
        .unwrap_or(key_id)
        .chars()
        .take(8)
        .collect()
}

/// Lowercase word for an incident status.
pub(crate) const fn status_word(status: IncidentStatus) -> &'static str {
    match status {
        IncidentStatus::Detected => "detected",
        IncidentStatus::Analyzing => "analyzing",
        IncidentStatus::Contained => "contained",
        IncidentStatus::Eradicated => "eradicated",
        IncidentStatus::Recovered => "recovered",
        IncidentStatus::Closed => "closed",
    }
}

/// A finding; `refused:` findings are agents declining an injected instruction.
fn finding_entry(summary: &str, evidence: usize, confidence_pct: u8) -> Entry {
    let (tag, tone) = if summary.starts_with("refused:") {
        ("REFUSED", Tone::Good)
    } else {
        ("FINDING", Tone::Warn)
    };
    Entry::new(
        tag,
        tone,
        format!("{summary} ({confidence_pct}%, {evidence} evidence)"),
    )
}

/// A commander's approval or denial on the bus.
const fn approval_entry(subject_id: String, approved: bool) -> Entry {
    if approved {
        Entry::new("APPROVED", Tone::Good, subject_id)
    } else {
        Entry::new("DENIED", Tone::Bad, subject_id)
    }
}

/// One agent loop step. A `denied: ` result is the kernel grant refusing the action.
fn trace_entry(step: u32, tool: &str, args: &Value, result: &str) -> Entry {
    let result = first_line(result);
    let (tag, tone) = if result.starts_with("denied: ") {
        ("BLOCKED BY OS", Tone::Bad)
    } else if result.starts_with("timed out") || result.starts_with("invalid arguments: ") {
        ("TRACE", Tone::Warn)
    } else if tool == "answer" {
        ("ANSWER", Tone::Plain)
    } else {
        ("TRACE", Tone::Quiet)
    };
    let args = summarize_args(args);
    let text = if args.is_empty() {
        format!("#{step} {tool} → {result}")
    } else {
        format!("#{step} {tool} {args} → {result}")
    };
    Entry::new(tag, tone, text)
}

/// A safety model's verdict on an untrusted artifact.
fn safety_entry(artifact: &str, model: &str, safe: bool, categories: &[String]) -> Entry {
    let (tone, verdict) = if safe {
        (Tone::Good, "safe")
    } else {
        (Tone::Bad, "UNSAFE")
    };
    let categories = if categories.is_empty() {
        String::new()
    } else {
        format!(" · {}", categories.join(", "))
    };
    Entry::new(
        "SAFETY",
        tone,
        format!("{verdict} {artifact}{categories} ({model})"),
    )
}

/// A model-routing decision.
fn route_entry(route: ModelRoute, reason: &str) -> Entry {
    let route = match route {
        ModelRoute::Local => "LOCAL model",
        ModelRoute::Hosted => "HOSTED model",
    };
    Entry::new("ROUTE", Tone::Quiet, format!("{route}: {reason}"))
}

/// The commander switching agent guardrails.
fn guardrails_entry(guardrails: bool) -> Entry {
    if guardrails {
        Entry::new(
            "GUARDRAILS",
            Tone::Good,
            "ON: hardened agent prompts".to_owned(),
        )
    } else {
        Entry::new(
            "GUARDRAILS",
            Tone::Bad,
            "OFF: naive agent prompts; only the kernel grant stands".to_owned(),
        )
    }
}

/// One-line description of an asset's flags.
fn scope_entry(record: &ScopeRecord) -> Entry {
    let flags = [
        ("LOCKED", record.flags.locked),
        ("EXFILTRATED", record.flags.exfiltrated),
        ("ACCESSED", record.flags.accessed),
        ("DESTROYED", record.flags.destroyed),
        ("MODIFIED", record.flags.modified),
    ];
    let hit: Vec<&str> = flags
        .iter()
        .filter(|(_, value)| *value == Tri::Yes)
        .map(|(name, _)| *name)
        .collect();
    let unknown = flags
        .iter()
        .filter(|(_, value)| *value == Tri::Unknown)
        .count();
    let name = &record.name;
    let confidence = record.confidence_pct;
    if !hit.is_empty() {
        let text = format!("{name}: {} ({confidence}% confidence)", hit.join(", "));
        Entry::new("SCOPE", Tone::Bad, text)
    } else if unknown > 0 {
        let text = format!("{name}: {unknown} flags unknown ({confidence}% confidence)");
        Entry::new("SCOPE", Tone::Warn, text)
    } else {
        Entry::new("SCOPE", Tone::Good, format!("{name}: clean"))
    }
}

/// Clock names whose trigger went from unset to set.
fn started_clocks(old: &Triggers, new: &Triggers) -> Vec<&'static str> {
    [
        (old.aware_at.is_none() && new.aware_at.is_some(), "GDPR 72h"),
        (
            old.discovered_at.is_none() && new.discovered_at.is_some(),
            "HIPAA 60-day",
        ),
        (
            old.breach_determined_at.is_none() && new.breach_determined_at.is_some(),
            "Texas §521.053",
        ),
        (
            old.materiality_determined_at.is_none() && new.materiality_determined_at.is_some(),
            "SEC 8-K",
        ),
    ]
    .into_iter()
    .filter_map(|(started, name)| started.then_some(name))
    .collect()
}

/// Parse the agent runtime's counters out of a status line.
///
/// The tokens are `blocked_by_model=<n> blocked_by_os=<n> safety_flags=<n>
/// guardrails=<on|off> llm=<mode>`. Returns `None` unless both blocked counters are present.
fn parse_counters(text: &str) -> Option<(Counters, Option<bool>)> {
    let mut by_model = None;
    let mut by_os = None;
    let mut safety_flags = 0;
    let mut guardrails = None;
    let mut llm = None;
    for (key, value) in text
        .split_whitespace()
        .filter_map(|token| token.split_once('='))
    {
        match key {
            "blocked_by_model" => by_model = value.parse().ok(),
            "blocked_by_os" => by_os = value.parse().ok(),
            "safety_flags" => safety_flags = value.parse().unwrap_or(0),
            "guardrails" => guardrails = Some(value == "on"),
            "llm" => llm = Some(value.to_owned()),
            _ => {}
        }
    }
    let counters = Counters {
        blocked_by_model: by_model?,
        blocked_by_os: by_os?,
        safety_flags,
        llm,
    };
    Some((counters, guardrails))
}

/// Compact display of a tool call's JSON arguments.
fn summarize_args(args: &Value) -> String {
    let text = match args {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Object(map) if map.len() == 1 => map.values().map(plain).collect(),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| format!("{key}={}", plain(value)))
            .collect::<Vec<_>>()
            .join(" "),
        Value::Bool(_) | Value::Number(_) | Value::Array(_) => args.to_string(),
    };
    truncate(&text, PREVIEW_CHARS)
}

/// A JSON value as plain text: strings unquoted, everything else as JSON.
fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            value.to_string()
        }
    }
}

/// The first line of `text`, truncated.
fn first_line(text: &str) -> String {
    truncate(text.lines().next().unwrap_or_default(), PREVIEW_CHARS)
}

/// At most `max` characters, with an ellipsis when cut.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}
