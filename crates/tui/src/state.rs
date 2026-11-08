//! The reducer: folds daemon frames into everything the command center shows.
//!
//! [`State::apply`] is the only way bus and daemon data enter. Live mode, replay mode and offline
//! renders all feed it the same [`Envelope`]s, so the screen depends on daemon frames alone.

use std::collections::{HashSet, VecDeque};

use cleanroom_proto::{
    Audience, BusBody, BusMessage, CoreResponse, Envelope, ExecOutcome, ExecResult, Frame,
    IncidentRecord, IncidentStatus, KeyId, LlmMode, MemberRole, ModelRoute, Principal, Role,
    ScopeFlags, ScopeRecord, ToolDecision, ToolRequest, ToolSource, Tri, Triggers, WIRE_VERSION,
};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::Value;

use crate::access::{Enrollment, Roster, Standing, role_word};
use crate::denials::{self, Denial, Kind, Reported, Traced, split_receipt};
use crate::team::{self, Team};

/// Agent-pane lines kept in memory.
const ACTIVITY_LIMIT: usize = 500;
/// Conversation entries kept in memory.
const TALK_LIMIT: usize = 400;
/// Longest text kept from a single trace argument or result.
const PREVIEW_CHARS: usize = 160;
/// Longest one-line summary of a message on an agent's card.
const CARD_CHARS: usize = 120;

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
    /// `enroll` a member with an admin-signed record.
    Enroll {
        /// `sha256:` of the member's key.
        key_id: KeyId,
        /// The member's raw public key, hex.
        public_key: String,
        /// Display name.
        name: String,
        /// Role.
        role: MemberRole,
    },
    /// `revoke` a member's key.
    Revoke {
        /// `sha256:` of the member's key.
        key_id: KeyId,
        /// Display name, when known.
        name: Option<String>,
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
            Self::Enroll { name, role, .. } => format!("Enroll {name} ({})", role_word(*role)),
            Self::Revoke { key_id, name } => format!(
                "Revoke {}",
                name.clone().unwrap_or_else(|| short_key(key_id))
            ),
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
    /// Everything the one-line text leaves out (full arguments, the whole result), shown when
    /// the line is expanded; empty when there is nothing more.
    pub(crate) detail: String,
}

/// One entry in the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Talk {
    /// A chat message.
    Said(Said),
    /// A key event, shown as one dim line.
    Marker(Marker),
}

/// A chat message and who it was for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Said {
    /// Local `HH:MM:SS`.
    pub(crate) at: String,
    /// Sender.
    pub(crate) from: Who,
    /// Audience.
    pub(crate) to: Audience,
    /// Message text.
    pub(crate) text: String,
}

/// A key system event in the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marker {
    /// Local `HH:MM:SS`.
    pub(crate) at: String,
    /// Emphasis.
    pub(crate) tone: Tone,
    /// The event.
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

/// Team-wide totals from the agent runtime's latest `counters` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counters {
    /// Injected instructions stopped by the model layer.
    pub(crate) blocked_by_model: u32,
    /// Actions the kernel grant denied.
    pub(crate) blocked_by_os: u32,
    /// Every unsafe safety verdict, guardrails on or off.
    pub(crate) safety_flags: u32,
    /// Where model responses come from; `replay` must be visible on screen.
    pub(crate) llm: LlmMode,
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
    /// What an expanded line adds.
    detail: String,
}

impl Entry {
    /// An entry tagged `tag` with nothing more to show when expanded.
    const fn new(tag: &'static str, tone: Tone, text: String) -> Self {
        Self {
            tag,
            tone,
            text,
            detail: String::new(),
        }
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
    /// The conversation: chat and key events, oldest first.
    pub(crate) talk: VecDeque<Talk>,
    /// Every OS denial this session.
    pub(crate) denials: denials::Log,
    /// The Lead and the specialists, as their events show them.
    pub(crate) team: Team,
    /// Members enrolled or revoked this session.
    pub(crate) roster: Roster,
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
            talk: VecDeque::new(),
            denials: denials::Log::default(),
            team: Team::default(),
            roster: Roster::default(),
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
    /// and offline renders pass `None`. `now` is the console's clock: it stamps lines that come
    /// from responses, which carry no time of their own, and times the banners and card states.
    pub fn apply(&mut self, envelope: Envelope, request: Option<&SentRequest>, now: Timestamp) {
        if envelope.v != WIRE_VERSION {
            self.notify(
                Tone::Warn,
                format!("Ignored a frame with wire version {}", envelope.v),
            );
            return;
        }
        match envelope.frame {
            Frame::Event(signed) => self.apply_message(signed.body, now),
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

    /// Whether something `role` asked for waits for the commander's signature.
    pub(crate) fn waiting_on(&self, role: Role) -> bool {
        self.queue
            .iter()
            .any(|item| item.sent.is_none() && item.from == Who::Agent(role))
    }

    /// Kernel and OS blocks this session: the runtime's count or the denials seen, whichever
    /// is higher (the runtime's count survives a console restart; the denials name each one).
    pub(crate) fn blocks(&self) -> u64 {
        let counted = self
            .counters
            .map_or(0, |counters| u64::from(counters.blocked_by_os));
        let seen = u64::try_from(self.denials.len()).unwrap_or(u64::MAX);
        counted.max(seen)
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
    #[allow(
        clippy::too_many_lines,
        reason = "one flat arm per bus message type reads clearer than splitting the dispatch. \
                  `allow`, not `expect`: the lint only runs under the strict profile"
    )]
    fn apply_message(&mut self, message: BusMessage, now: Timestamp) {
        let origin = Origin {
            at: self.time_label(&message.at),
            who: self.who(&message.from),
        };
        match message.body {
            BusBody::Chat { text } => self.chat(origin, message.to, text, now),
            BusBody::Finding {
                summary,
                evidence,
                confidence_pct,
            } => {
                if let Who::Agent(role) = origin.who {
                    self.team
                        .noted(role, format!("found: {}", one_line(&summary)));
                }
                let found = format!("{} found: {summary}", who_title(&origin.who));
                self.mark(&origin, Tone::Warn, found);
                let text = format!("{summary} ({confidence_pct}%, {} evidence)", evidence.len());
                self.log(&origin, Entry::new("FINDING", Tone::Warn, text));
            }
            BusBody::Proposal {
                proposal_id,
                action,
                rationale,
            } => {
                if let Who::Agent(role) = origin.who {
                    self.team.noted(role, format!("proposes: {action}"));
                }
                let proposes = format!(
                    "{} proposes: {action} · waiting for your signature",
                    who_title(&origin.who)
                );
                self.mark(&origin, Tone::Warn, proposes);
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
                outcome,
            } => {
                let entry = trace_entry(step, &tool, &args, &result_preview, outcome.as_ref());
                if let Who::Agent(role) = origin.who {
                    self.team.step(role, &tool, entry.text.clone(), now);
                    if let Some(ExecOutcome::Denied { reason }) = outcome {
                        let traced = Traced {
                            role,
                            step,
                            command: summarize_args(&args),
                            reason,
                            receipt: split_receipt(&result_preview).1,
                        };
                        self.denied_step(&origin, traced, now);
                    }
                }
                self.log(&origin, entry);
            }
            BusBody::Refusal {
                artifact,
                instruction,
            } => {
                let refused = format!("refused \"{}\" in {artifact}", one_line(&instruction));
                if let Who::Agent(role) = origin.who {
                    self.team.refused(role, refused.clone(), now);
                }
                let marker = format!("{} {refused}: blocked by the model", who_title(&origin.who));
                self.mark(&origin, Tone::Good, marker);
                let text = format!("blocked by the model: \"{instruction}\" in {artifact}");
                self.log(&origin, Entry::new("REFUSED", Tone::Good, text));
            }
            BusBody::Counters {
                blocked_by_model,
                blocked_by_os,
                safety_flags,
                guardrails,
                llm,
            } => {
                self.counters = Some(Counters {
                    blocked_by_model,
                    blocked_by_os,
                    safety_flags,
                    llm,
                });
                self.guardrails = guardrails;
            }
            BusBody::SafetyVerdict {
                artifact,
                model,
                safe,
                categories,
            } => self.log(&origin, safety_entry(&artifact, &model, safe, &categories)),
            BusBody::Route { route, reason } => {
                if let Who::Agent(role) = origin.who {
                    self.team.route(role, route);
                }
                self.log(&origin, route_entry(route, &reason));
            }
            BusBody::Scope(record) => self.scope_update(&origin, record),
            BusBody::Incident(record) => self.incident_update(&origin, record),
            BusBody::Status { text } => self.status(&origin, text, now),
            BusBody::Investigate { incident_id, brief } => {
                self.team.investigate(now);
                self.mark(
                    &origin,
                    Tone::Plain,
                    format!("investigation started on {incident_id}"),
                );
                let text = format!("{incident_id}: {brief}");
                self.log(&origin, Entry::new("INVESTIGATE", Tone::Plain, text));
                self.investigating = Some(incident_id);
            }
            BusBody::AgentControl { guardrails } => {
                self.guardrails = guardrails;
                let entry = guardrails_entry(guardrails);
                let tone = if guardrails { Tone::Good } else { Tone::Warn };
                self.mark(&origin, tone, format!("guardrails {}", entry.text));
                self.log(&origin, entry);
            }
        }
    }

    /// A chat message: into the conversation, and onto the cards of who spoke and who was asked.
    fn chat(&mut self, origin: Origin, to: Audience, text: String, now: Timestamp) {
        let summary = one_line(&text);
        match (&origin.who, &to) {
            (Who::Agent(Role::Lead), Audience::Role { role }) if *role != Role::Lead => {
                let line = format!("asked {}: {summary}", team::title(*role));
                self.team.delegated(*role, line, now);
            }
            (Who::Agent(role), _) => {
                let line = format!("→ {}: {summary}", audience_title(&to));
                self.team.spoke(*role, line);
            }
            (Who::Me | Who::Human(_), Audience::Role { role }) => {
                self.team.asked_by_human(*role, now);
            }
            (Who::Me | Who::Human(_) | Who::System, _) => {}
        }
        let Origin { at, who } = origin;
        push_capped(
            &mut self.talk,
            Talk::Said(Said {
                at,
                from: who,
                to,
                text,
            }),
            TALK_LIMIT,
        );
    }

    /// A status line: cleanroomd's become conversation markers (and denials, and members); the
    /// agent runtime's announce models and the end of an investigation.
    fn status(&mut self, origin: &Origin, text: String, now: Timestamp) {
        match &origin.who {
            Who::System => {
                if let Some(reported) = denials::parse_status(&text) {
                    self.denied(origin, reported, now);
                } else {
                    self.roster.status(&text);
                    self.mark(origin, Tone::Quiet, text.clone());
                }
            }
            Who::Agent(_) => {
                if text.contains("models: ") {
                    self.team.models(models(&text));
                }
                let finished = text.contains("agents offline")
                    || (text.contains("investigation ") && text.contains(" finished"));
                if finished {
                    self.team.finished();
                }
            }
            Who::Me | Who::Human(_) => {}
        }
        self.log(origin, Entry::new("STATUS", Tone::Plain, text));
    }

    /// cleanroomd reported a denial.
    fn denied(&mut self, origin: &Origin, reported: Reported, now: Timestamp) {
        let fresh = self
            .denials
            .reported(reported, origin.at.clone(), now)
            .map(|denial| (denial.role, denial_marker(denial)));
        self.announce_denial(origin, fresh, now);
    }

    /// An agent's trace says the grant denied its step.
    fn denied_step(&mut self, origin: &Origin, traced: Traced, now: Timestamp) {
        let fresh = self
            .denials
            .traced(traced, origin.at.clone(), now)
            .map(|denial| (denial.role, denial_marker(denial)));
        self.announce_denial(origin, fresh, now);
    }

    /// Flash a new denial on its agent's card and mark it in the conversation.
    fn announce_denial(
        &mut self,
        origin: &Origin,
        fresh: Option<(Option<Role>, String)>,
        now: Timestamp,
    ) {
        if let Some((role, text)) = fresh {
            if let Some(role) = role {
                self.team.blocked(role, now);
            }
            self.mark(origin, Tone::Bad, text);
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
                let origin = self.system_origin(now);
                self.mark(&origin, Tone::Bad, format!("admission rejected: {text}"));
                self.log(&origin, Entry::new("ADMISSION", Tone::Bad, text.clone()));
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
                let origin = self.system_origin(now);
                self.mark(&origin, Tone::Good, text.clone());
                self.log(&origin, Entry::new("ADMISSION", Tone::Good, text.clone()));
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
                format!("Detonated {scenario} in the sacrificial stratum. Watch the scope."),
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
            Some(
                request @ SentRequest::Enroll {
                    key_id,
                    public_key,
                    name,
                    role,
                },
            ) => {
                self.roster.enrolled(Enrollment {
                    key_id: key_id.clone(),
                    public_key: Some(public_key.clone()),
                    name: Some(name.clone()),
                    role: Some(*role),
                    standing: Standing::Enrolled,
                    receipt: None,
                });
                self.notify(Tone::Good, format!("{}: ok", request.describe()));
            }
            Some(request @ SentRequest::Revoke { key_id, .. }) => {
                self.roster.revoked(key_id, None);
                self.notify(Tone::Good, format!("{}: ok", request.describe()));
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

    /// Forget everything about the previous run. Guardrails, identity and the roster survive:
    /// they belong to the agents, this console and cleanroomd's member list, not to the
    /// incident. Scope survives too: cleanroomd republishes every asset's all-`no` baseline on
    /// reset, possibly before its `ok`, and those records replace the old ones by asset id.
    fn clear(&mut self) {
        self.incident = None;
        self.activity.clear();
        self.talk.clear();
        self.denials.clear();
        self.team.clear();
        self.queue.clear();
        self.decided.clear();
        self.counters = None;
        self.log = LogStatus::Unverified;
        self.admission = None;
        self.investigating = None;
    }

    /// A `tool_request` message. cleanroomd publishes it, so the queue and the agent pane credit
    /// the requesting role named inside the request.
    fn tool_request(&mut self, origin: &Origin, request: ToolRequest) {
        let ToolRequest {
            id,
            from,
            tool,
            source,
            reason,
            ..
        } = request;
        let source = match source {
            ToolSource::Nix { flake_ref } => format!("nix {flake_ref}"),
            ToolSource::Oci { image, manifest } => format!("oci {image}@{manifest}"),
        };
        self.team.noted(from, format!("asked for {tool}"));
        let text = format!("needs {tool} ({source}): {reason}");
        let ask = Ask::Tool {
            tool,
            source,
            reason,
        };
        let requester = Origin {
            at: origin.at.clone(),
            who: Who::Agent(from),
        };
        self.enqueue(id, requester.who.clone(), ask);
        self.log(&requester, Entry::new("TOOL REQUEST", Tone::Warn, text));
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
        if tone == Tone::Warn {
            let marker = self
                .queue
                .iter()
                .find(|item| item.subject_id == request_id)
                .and_then(|item| match &item.ask {
                    Ask::Tool { tool, .. } => Some(format!(
                        "{} wants {tool}: outside policy, waiting for your signature",
                        who_title(&item.from)
                    )),
                    Ask::Proposal { .. } => None,
                })
                .unwrap_or_else(|| text.clone());
            self.mark(origin, Tone::Warn, marker);
        } else {
            self.settle(request_id);
        }
        self.log(origin, Entry::new("TOOL", tone, text));
    }

    /// A full scope record for one asset. Logs a line when its flags change and marks the
    /// conversation when the asset becomes compromised (or stops being).
    fn scope_update(&mut self, origin: &Origin, record: ScopeRecord) {
        let index = self
            .scope
            .iter()
            .position(|asset| asset.asset_id == record.asset_id);
        let old = index.and_then(|index| self.scope.get(index));
        let changed = old.is_none_or(|old| old.flags != record.flags);
        let was_hit = old.is_some_and(|old| compromised(old.flags));
        if changed {
            self.log(origin, scope_entry(&record));
        }
        let hit = compromised(record.flags);
        if hit && !was_hit {
            let flags = yes_flags(record.flags).join(", ");
            let text = format!("{} compromised: {flags}", record.name);
            self.mark(origin, Tone::Bad, text);
        } else if was_hit && !hit {
            let text = format!("{}: no flag set any more", record.name);
            self.mark(origin, Tone::Good, text);
        }
        match index.and_then(|index| self.scope.get_mut(index)) {
            Some(slot) => *slot = record,
            None => self.scope.push(record),
        }
    }

    /// A full incident record. Logs and marks declarations, status changes and newly started
    /// clocks.
    fn incident_update(&mut self, origin: &Origin, record: IncidentRecord) {
        let previous = self.incident.take();
        let status = status_word(record.status);
        match &previous {
            Some(old) if old.id == record.id => {
                if old.status != record.status {
                    let text = format!("{} is now {status}", record.id);
                    self.mark(origin, Tone::Warn, format!("incident {text}"));
                    self.log(origin, Entry::new("INCIDENT", Tone::Warn, text));
                }
            }
            Some(_) | None => {
                let text = format!("{} declared: {} ({status})", record.id, record.title);
                self.mark(origin, Tone::Bad, format!("incident {text}"));
                self.log(origin, Entry::new("INCIDENT", Tone::Bad, text));
            }
        }
        let old_triggers = previous.map(|old| old.triggers).unwrap_or_default();
        for name in started_clocks(&old_triggers, &record.triggers) {
            let text = format!("{name} clock started");
            self.mark(origin, Tone::Warn, text.clone());
            self.log(origin, Entry::new("LEGAL CLOCK", Tone::Warn, text));
        }
        self.incident = Some(record);
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
            detail: entry.detail,
        };
        push_capped(&mut self.activity, activity, ACTIVITY_LIMIT);
    }

    /// Mark a key event in the conversation.
    fn mark(&mut self, origin: &Origin, tone: Tone, text: String) {
        let marker = Marker {
            at: origin.at.clone(),
            tone,
            text,
        };
        push_capped(&mut self.talk, Talk::Marker(marker), TALK_LIMIT);
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

/// `Hunter`, `cleanroomd`, `you`, `human 1b809d1d`: a sender in a sentence.
pub(crate) fn who_title(who: &Who) -> String {
    match who {
        Who::Agent(role) => team::title(*role).to_owned(),
        Who::System => "cleanroomd".to_owned(),
        Who::Me => "you".to_owned(),
        Who::Human(short) => format!("human {short}"),
    }
}

/// `Lead`, `Hunter`, `you`, `team`: an audience in a sentence.
pub(crate) const fn audience_title(to: &Audience) -> &'static str {
    match to {
        Audience::Role { role } => team::title(*role),
        Audience::Humans => "you",
        Audience::All => "team",
    }
}

/// One line of a message for a card: markdown emphasis dropped, whitespace collapsed, clipped.
pub(crate) fn one_line(text: &str) -> String {
    let plain: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate(&plain.replace("**", "").replace('`', ""), CARD_CHARS)
}

/// `role=model` pairs from the agent runtime's "agents online …; models: lead=…, hunter=…" line.
fn models(text: &str) -> Vec<(Role, String)> {
    let Some((_, list)) = text.split_once("models: ") else {
        return Vec::new();
    };
    let list = list.split_once(';').map_or(list, |(list, _)| list);
    list.split(',')
        .filter_map(|pair| pair.trim().split_once('='))
        .filter_map(|(role, model)| {
            denials::role_named(role.trim()).map(|role| (role, model.trim().to_owned()))
        })
        .collect()
}

/// The conversation's line for a denial.
fn denial_marker(denial: &Denial) -> String {
    let receipt = denial
        .receipt
        .map(|seq| format!(" · receipt #{seq}"))
        .unwrap_or_default();
    match denial.kind {
        Kind::Exec => format!(
            "kernel blocked {}: {} · {}{receipt}",
            denial.who,
            denial.command,
            denial.short_reason()
        ),
        Kind::Record => format!(
            "cleanroomd kept the record: {} tried to {}{receipt}",
            denial.who, denial.command
        ),
    }
}

/// Whether any flag says the asset was hit.
pub(crate) fn compromised(flags: ScopeFlags) -> bool {
    [
        flags.locked,
        flags.exfiltrated,
        flags.accessed,
        flags.destroyed,
        flags.modified,
    ]
    .contains(&Tri::Yes)
}

/// Names of the flags that are `yes`, most severe first.
pub(crate) fn yes_flags(flags: ScopeFlags) -> Vec<&'static str> {
    [
        ("EXFILTRATED", flags.exfiltrated),
        ("DESTROYED", flags.destroyed),
        ("LOCKED", flags.locked),
        ("MODIFIED", flags.modified),
        ("ACCESSED", flags.accessed),
    ]
    .into_iter()
    .filter(|(_, value)| *value == Tri::Yes)
    .map(|(name, _)| name)
    .collect()
}

/// A commander's approval or denial on the bus.
const fn approval_entry(subject_id: String, approved: bool) -> Entry {
    if approved {
        Entry::new("APPROVED", Tone::Good, subject_id)
    } else {
        Entry::new("DENIED", Tone::Bad, subject_id)
    }
}

/// One agent loop step on one line: `#5 exec rm -rf /evidence/* → BLOCKED (read-only)`. The
/// full arguments and result go into the detail an expanded line shows.
fn trace_entry(
    step: u32,
    tool: &str,
    args: &Value,
    result: &str,
    outcome: Option<&ExecOutcome>,
) -> Entry {
    let summary = summarize_args(args);
    let call = if summary.is_empty() {
        format!("#{step} {tool}")
    } else {
        format!("#{step} {tool} {summary}")
    };
    let detail = trace_detail(args, result, outcome);
    let (tag, tone, text) = match outcome {
        Some(ExecOutcome::Denied { reason }) => (
            "BLOCKED BY OS",
            Tone::Bad,
            format!("{call} → BLOCKED ({})", denials::short_reason(reason)),
        ),
        Some(ExecOutcome::TimedOut) => ("TRACE", Tone::Warn, format!("{call} → timed out")),
        Some(ExecOutcome::Exited { .. }) | None if tool == "answer" => (
            "ANSWER",
            Tone::Plain,
            format!("{call} → {}", first_line(result)),
        ),
        Some(ExecOutcome::Exited { .. }) | None => (
            "TRACE",
            Tone::Quiet,
            format!("{call} → {}", first_line(result)),
        ),
    };
    Entry {
        tag,
        tone,
        text,
        detail,
    }
}

/// Everything about a step: the exit, the denial reason, the full arguments and the result.
fn trace_detail(args: &Value, result: &str, outcome: Option<&ExecOutcome>) -> String {
    let outcome = match outcome {
        Some(ExecOutcome::Denied { reason }) => format!("denied by the stratum grant: {reason}\n"),
        Some(ExecOutcome::Exited { code }) => format!("exit {code}\n"),
        Some(ExecOutcome::TimedOut) => "timed out\n".to_owned(),
        None => String::new(),
    };
    let args = match args {
        Value::Null => String::new(),
        Value::Object(map) if map.is_empty() => String::new(),
        Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_)
        | Value::Object(_) => format!("args {args}\n"),
    };
    format!("{outcome}{args}{}", result.trim_end())
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
        record.flags.locked,
        record.flags.exfiltrated,
        record.flags.accessed,
        record.flags.destroyed,
        record.flags.modified,
    ];
    let hit = yes_flags(record.flags);
    let unknown = flags.iter().filter(|value| **value == Tri::Unknown).count();
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
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}
