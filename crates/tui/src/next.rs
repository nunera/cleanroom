//! "What do I do now": the single next step for the commander, computed from state.

use jiff::{SignedDuration, Timestamp};

use crate::clocks::{self, ClockState, Regime, Urgency};
use crate::state::{Admission, LogStatus, State};

/// The one thing the commander should do next, most pressing first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NextAction {
    /// The live connection to cleanroomd is gone.
    Reconnect,
    /// The receipt chain is broken.
    LogBroken {
        /// First receipt that doesn't chain.
        first_break: u64,
    },
    /// The last admission was rejected; the clean copy should be admitted again.
    Readmit {
        /// The rejected root.
        root: String,
    },
    /// Tool requests or proposals wait for a signature.
    Approvals {
        /// How many.
        count: usize,
    },
    /// A legal clock is running; `urgency` says how close it is.
    Clock {
        /// Which regime.
        regime: Regime,
        /// Time left (negative when overdue).
        remaining: SignedDuration,
        /// The deadline.
        due: Timestamp,
        /// How close the deadline is.
        urgency: Urgency,
    },
    /// An incident exists but the agent team hasn't been started on it.
    Investigate,
    /// Nothing has happened yet.
    Detonate,
    /// Agents are working and nothing needs the commander.
    Watch,
}

/// Pick the next action. `connected` is false only when a live link has dropped.
///
/// Order: a dead link or broken log first (nothing else can be trusted), then a rejected root
/// (the toolkit isn't admitted until its clean copy is), then approvals (agents are blocked on
/// them), then clocks due within a day or overdue, then starting the agent team, then the
/// soonest running clock.
pub(crate) fn next_action(state: &State, connected: bool, now: Timestamp) -> NextAction {
    if !connected {
        return NextAction::Reconnect;
    }
    if let LogStatus::Broken { first_break, .. } = state.log {
        return NextAction::LogBroken { first_break };
    }
    if let Some(Admission::Rejected { root, .. }) = &state.admission {
        return NextAction::Readmit { root: root.clone() };
    }
    let waiting = state.waiting();
    if waiting > 0 {
        return NextAction::Approvals { count: waiting };
    }
    let soonest = soonest_clock(state, now);
    if let Some(clock @ NextAction::Clock { urgency, .. }) = &soonest
        && *urgency >= Urgency::Urgent
    {
        return clock.clone();
    }
    match &state.incident {
        None => NextAction::Detonate,
        Some(incident) if state.investigating.as_ref() != Some(&incident.id) => {
            NextAction::Investigate
        }
        Some(_) => soonest.unwrap_or(NextAction::Watch),
    }
}

/// The running clock with the nearest deadline.
fn soonest_clock(state: &State, now: Timestamp) -> Option<NextAction> {
    clocks::clocks(&state.triggers(), &state.scope)
        .into_iter()
        .filter_map(|clock| match clock.state {
            ClockState::Running { due } => Some((clock.regime, due)),
            ClockState::NotStarted | ClockState::NotApplicable(_) | ClockState::BadTrigger => None,
        })
        .min_by_key(|(_, due)| *due)
        .map(|(regime, due)| {
            let remaining = due.duration_since(now);
            NextAction::Clock {
                regime,
                remaining,
                due,
                urgency: clocks::urgency(remaining),
            }
        })
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{
        Audience, BusBody, BusMessage, CoreResponse, DataClass, Envelope, Frame, IncidentRecord,
        IncidentStatus, Principal, Role, ScopeFlags, ScopeRecord, Severity, Signed, ToolRequest,
        ToolSource, Tri, Triggers, WIRE_VERSION,
    };
    use jiff::tz::TimeZone;

    use super::*;

    fn now() -> Timestamp {
        "2026-11-07T21:00:00Z".parse().expect("fixed test time")
    }

    fn event(body: BusBody) -> Envelope {
        let message = BusMessage {
            id: "m".into(),
            at: "2026-11-07T20:00:00Z".into(),
            from: Principal::Agent {
                role: Role::Forensics,
            },
            to: Audience::All,
            body,
        };
        Envelope {
            v: WIRE_VERSION,
            frame: Frame::Event(Signed {
                domain: cleanroom_proto::domain::BUS.into(),
                body: message,
                signer: "sha256:00".into(),
                sig: "00".into(),
            }),
        }
    }

    fn incident(triggers: Triggers) -> BusBody {
        BusBody::Incident(IncidentRecord {
            id: "INC-7".into(),
            title: "Ransomware on acme-fs".into(),
            status: IncidentStatus::Analyzing,
            severity: Severity::Critical,
            category: "ransomware".into(),
            detected_at: "2026-11-07T20:00:00Z".into(),
            reported_by: Principal::System,
            summary: "Canaries encrypted".into(),
            affected_systems: vec!["acme-fs".into()],
            triggers,
            timeline: Vec::new(),
        })
    }

    fn texans(count: u64) -> BusBody {
        BusBody::Scope(ScopeRecord {
            asset_id: "hr".into(),
            name: "employees.csv".into(),
            data_classes: vec![DataClass::Pii],
            record_count: count,
            texas_residents: count,
            flags: ScopeFlags {
                locked: Tri::Yes,
                ..ScopeFlags::default()
            },
            encrypted_at_rest: false,
            key_exposed: Tri::Unknown,
            confidence_pct: 90,
            evidence: Vec::new(),
            updated_by: Principal::System,
            updated_at: "2026-11-07T20:00:00Z".into(),
        })
    }

    fn tool_request() -> BusBody {
        BusBody::ToolRequest(ToolRequest {
            id: "tool-03".into(),
            from: Role::Forensics,
            stratum: "forensics".into(),
            tool: "volatility3".into(),
            source: ToolSource::Nix {
                flake_ref: "github:NixOS/nixpkgs/abc#volatility3".into(),
            },
            reason: "memory image analysis".into(),
        })
    }

    fn state_with(bodies: Vec<BusBody>) -> State {
        let mut state = State::new(TimeZone::UTC);
        for body in bodies {
            state.apply(event(body), None, now());
        }
        state
    }

    fn investigate() -> BusBody {
        BusBody::Investigate {
            incident_id: "INC-7".into(),
            brief: "go".into(),
        }
    }

    fn texas_breach() -> Triggers {
        Triggers {
            breach_determined_at: Some("2026-11-07T20:00:00Z".into()),
            ..Triggers::default()
        }
    }

    #[test]
    fn quiet_start_suggests_detonation() {
        assert_eq!(
            next_action(&state_with(vec![]), true, now()),
            NextAction::Detonate
        );
    }

    #[test]
    fn approvals_come_before_clocks_then_the_soonest_clock_shows() {
        let mut state = state_with(vec![
            incident(texas_breach()),
            texans(300),
            investigate(),
            tool_request(),
        ]);
        assert_eq!(
            next_action(&state, true, now()),
            NextAction::Approvals { count: 1 }
        );

        state.apply(
            event(BusBody::Approval {
                subject_id: "tool-03".into(),
                approved: true,
            }),
            None,
            now(),
        );
        let NextAction::Clock {
            regime, remaining, ..
        } = next_action(&state, true, now())
        else {
            panic!("a running clock should be next");
        };
        assert_eq!(
            regime,
            Regime::TexasAg,
            "30-day AG notice beats 60-day notice"
        );
        assert_eq!(remaining, SignedDuration::from_hours(30 * 24 - 1));
    }

    #[test]
    fn below_the_texas_threshold_the_individual_notice_is_next() {
        let state = state_with(vec![incident(texas_breach()), texans(249), investigate()]);
        assert!(matches!(
            next_action(&state, true, now()),
            NextAction::Clock {
                regime: Regime::TexasIndividuals,
                ..
            }
        ));
    }

    #[test]
    fn an_urgent_clock_outranks_starting_the_investigation() {
        // Aware 49 hours ago: 23 hours of the GDPR 72 remain.
        let triggers = Triggers {
            aware_at: Some("2026-11-05T20:00:00Z".into()),
            ..Triggers::default()
        };
        let state = state_with(vec![incident(triggers)]);
        assert!(matches!(
            next_action(&state, true, now()),
            NextAction::Clock {
                regime: Regime::Gdpr,
                urgency: Urgency::Urgent,
                ..
            }
        ));
        let calm = state_with(vec![incident(texas_breach())]);
        assert_eq!(next_action(&calm, true, now()), NextAction::Investigate);
    }

    #[test]
    fn a_dropped_link_outranks_everything() {
        let state = state_with(vec![tool_request()]);
        assert_eq!(next_action(&state, false, now()), NextAction::Reconnect);
    }

    #[test]
    fn a_rejected_root_asks_for_a_clean_admission_until_one_succeeds() {
        let response = |response| Envelope {
            v: WIRE_VERSION,
            frame: Frame::Response { id: 2, response },
        };
        let mut state = state_with(vec![tool_request()]);
        state.apply(
            response(CoreResponse::AdmitRejected {
                root: "debian".into(),
                layer: "sha256:aa".into(),
                expected: "sha256:bb".into(),
                actual: "sha256:cc".into(),
            }),
            None,
            now(),
        );
        assert_eq!(
            next_action(&state, true, now()),
            NextAction::Readmit {
                root: "debian".into()
            },
            "a tampered root outranks waiting approvals"
        );
        state.apply(
            response(CoreResponse::Admitted {
                root: "debian".into(),
                manifest: "sha256:bb".into(),
            }),
            None,
            now(),
        );
        assert_eq!(
            next_action(&state, true, now()),
            NextAction::Approvals { count: 1 }
        );
    }
}
