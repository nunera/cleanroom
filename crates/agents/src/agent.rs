//! One agent's tool-calling loop.
//!
//! Each step asks the model, checks every tool call against the schema the model was shown,
//! runs it in the role's stratum through `cleanroomd`, and publishes a `trace`. Tool output that
//! carries evidence is screened before any model sees it: personal data or credentials taint
//! the conversation and route it to the local model, the safety model scores the text, and with
//! guardrails on an unsafe verdict wraps it in an untrusted-data envelope.

use std::sync::Arc;
use std::time::Duration;

use cleanroom_proto::{
    BusBody, CoreRequest, CoreResponse, ExecOutcome, ExecRequest, ExecResult, ModelRoute, Role,
    ToolDecision, ToolRequest, ToolSource,
};
use serde_json::{Map, Value};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, watch};

use crate::cache::Hit;
use crate::config::CacheMode;
use crate::daemon::{Connection, now};
use crate::llm::{Message, Origin, Reply, Router, ToolCall};
use crate::records::{Case, Records};
use crate::roles;
use crate::safety::{self, Counters};
use crate::sensitivity::{self, Detector};
use crate::text::{clip, preview};
use crate::tools::{
    self, Action, Call, ExecSpec, FindingArgs, IncidentUpdate, Prepared, ProposalArgs, Rejection,
    ScopeUpdate, ToolAsk, ToolSpec,
};

/// Characters of tool output a model sees at most.
const MODEL_TEXT_LIMIT: usize = 12_000;
/// Characters in a trace preview.
const PREVIEW_CHARS: usize = 160;
/// Extra wait beyond the daemon-side exec timeout.
const EXEC_GRACE: Duration = Duration::from_secs(10);
/// How long the daemon may take to answer `request_tool`.
const TOOL_REQUEST_WAIT: Duration = Duration::from_secs(30);
/// How long a pending tool request waits for the commander.
const TOOL_DECISION_WAIT: Duration = Duration::from_secs(90);
/// Model calls left in a loop when the agent is told to wrap up.
const WRAP_UP_CALLS: u32 = 2;

/// A bus event other tasks wait on.
#[derive(Debug, Clone)]
pub(crate) enum Control {
    /// The daemon or commander decided a tool request.
    ToolDecision {
        /// Which request.
        request_id: String,
        /// The decision.
        decision: ToolDecision,
    },
    /// The commander approved or rejected a proposal.
    Approval {
        /// Proposal id.
        subject_id: String,
        /// Approved or not.
        approved: bool,
    },
}

/// What Scribe hears from the rest of the team.
#[derive(Debug, Clone)]
pub(crate) enum Note {
    /// A finding from Hunter or Forensics.
    Finding {
        /// Who found it.
        from: Role,
        /// The finding.
        finding: FindingArgs,
    },
    /// A containment proposal.
    Proposal {
        /// Proposal id.
        proposal_id: String,
        /// The proposal.
        proposal: ProposalArgs,
    },
    /// The commander's decision on a proposal.
    Decision {
        /// Proposal id.
        proposal_id: String,
        /// The proposed action.
        action: String,
        /// Approved or rejected.
        approved: bool,
    },
}

/// Everything the agents share for the life of the runner.
#[derive(Debug)]
pub(crate) struct Shared {
    /// Model router.
    pub(crate) router: Router,
    /// Personal data and credential detector.
    pub(crate) detector: Detector,
    /// Injection counters.
    pub(crate) counters: Counters,
    /// Current guardrails setting.
    pub(crate) guardrails: watch::Receiver<bool>,
    /// Tool decisions and approvals from the bus.
    pub(crate) control: broadcast::Sender<Control>,
    /// Model calls per conversation.
    pub(crate) max_steps: u32,
    /// Flake reference prefix for tool requests.
    pub(crate) nixpkgs: String,
}

impl Shared {
    /// Guardrails right now.
    pub(crate) fn guardrails(&self) -> bool {
        *self.guardrails.borrow()
    }

    /// The counters status line the TUI parses.
    pub(crate) fn counters_line(&self) -> String {
        let counts = self.counters.snapshot();
        format!(
            "injections blocked_by_model={} blocked_by_os={} safety_flags={} guardrails={} llm={}",
            counts.blocked_by_model,
            counts.blocked_by_os,
            counts.safety_flags,
            on_off(self.guardrails()),
            self.router.mode().label()
        )
    }

    /// Prefix status text in replay mode so nobody mistakes recorded output for a live model.
    pub(crate) fn label(&self, text: String) -> String {
        if self.router.mode() == CacheMode::Replay {
            format!("[llm replay: recorded responses, no live model] {text}")
        } else {
            text
        }
    }
}

/// `on` or `off`.
pub(crate) const fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

/// What one role accumulates during one investigation.
#[derive(Debug)]
pub(crate) struct Desk {
    /// The incident.
    pub(crate) case: Arc<Case>,
    /// Model calls so far, across conversations (trace step numbers).
    steps: u32,
    /// The route last announced on the bus.
    route: Option<ModelRoute>,
    /// Findings this role reported.
    pub(crate) findings: Vec<FindingArgs>,
    /// Proposals this role made: id and action.
    pub(crate) proposals: Vec<(String, String)>,
    /// Tool requests so far.
    tool_requests: u32,
    /// Scribe's records.
    pub(crate) records: Records,
    /// Where findings and proposals go (to Scribe).
    notes: Option<mpsc::UnboundedSender<Note>>,
    /// Whether this desk already announced a replay by position.
    replay_noted: bool,
}

impl Desk {
    /// A fresh desk for `case`.
    pub(crate) fn new(case: Arc<Case>, notes: Option<mpsc::UnboundedSender<Note>>) -> Self {
        Self {
            case,
            steps: 0,
            route: None,
            findings: Vec::new(),
            proposals: Vec::new(),
            tool_requests: 0,
            records: Records::default(),
            notes,
            replay_noted: false,
        }
    }

    /// Forward a note to Scribe, if this desk reports to Scribe.
    fn forward(&self, note: Note) {
        if let Some(notes) = &self.notes
            && notes.send(note).is_err()
        {
            tracing::debug!("scribe already finished; note dropped");
        }
    }
}

/// One conversation's state.
#[derive(Debug)]
struct Thread {
    /// Messages so far.
    messages: Vec<Message>,
    /// Guardrails the current system prompt reflects.
    guardrails: bool,
    /// Personal data or credentials entered this conversation.
    sensitive: bool,
}

/// A finished tool call: what the model reads back and what the trace shows.
#[derive(Debug)]
struct Done {
    /// Text for the model.
    text: String,
    /// Trace preview.
    preview: String,
    /// The text carries evidence and must be screened before a model sees it.
    untrusted: bool,
}

impl Done {
    /// A runner-authored result.
    fn ok(text: String) -> Self {
        Self {
            preview: preview(&text, PREVIEW_CHARS),
            text,
            untrusted: false,
        }
    }

    /// A failure the model should know about.
    fn error(reason: &str) -> Self {
        Self {
            text: format!("error: {reason}"),
            preview: preview(&format!("error: {reason}"), PREVIEW_CHARS),
            untrusted: false,
        }
    }
}

/// One role's model loop, speaking through its own connection.
#[derive(Debug)]
pub(crate) struct Agent {
    /// Who this is.
    role: Role,
    /// The role's daemon connection.
    conn: Arc<Connection>,
    /// Team-wide state.
    shared: Arc<Shared>,
    /// Tools under the hardened prompt.
    hardened: Vec<ToolSpec>,
    /// Tools under the naive prompt.
    naive: Vec<ToolSpec>,
}

impl Agent {
    /// An agent for `role`.
    pub(crate) fn new(role: Role, conn: Arc<Connection>, shared: Arc<Shared>) -> Self {
        Self {
            role,
            conn,
            shared,
            hardened: roles::tool_specs(role, true),
            naive: roles::tool_specs(role, false),
        }
    }

    /// Tools offered under the given guardrails setting.
    fn tools(&self, guardrails: bool) -> &[ToolSpec] {
        if guardrails {
            &self.hardened
        } else {
            &self.naive
        }
    }

    /// Run one conversation on `task` until the model answers without tools or the step cap.
    pub(crate) async fn converse(&self, desk: &mut Desk, task: String) {
        let guardrails = self.shared.guardrails();
        let mut thread = Thread {
            messages: Vec::with_capacity(
                2 + 2 * usize::try_from(self.shared.max_steps).unwrap_or(0),
            ),
            guardrails,
            sensitive: false,
        };
        self.check_sensitive(desk, &mut thread, &task).await;
        thread.messages.push(Message::System {
            content: roles::system_prompt(self.role, guardrails),
        });
        thread.messages.push(Message::User { content: task });
        for remaining in (1..=self.shared.max_steps).rev() {
            self.follow_guardrails(&mut thread).await;
            if remaining == WRAP_UP_CALLS && self.shared.max_steps > WRAP_UP_CALLS {
                thread.messages.push(Message::User {
                    content: format!(
                        "You have {remaining} model calls left in this loop. Make the tool calls that matter most now (report findings you have not reported, record updates, proposals), then reply with a short summary and no tool call."
                    ),
                });
            }
            desk.steps += 1;
            let route = self.route(desk, &thread).await;
            let reply = match self
                .shared
                .router
                .chat(
                    self.role,
                    route,
                    &thread.messages,
                    self.tools(thread.guardrails),
                )
                .await
            {
                Ok(reply) => reply,
                Err(error) => {
                    self.status(format!(
                        "{} stopped: model call failed: {error:#}",
                        self.name()
                    ))
                    .await;
                    return;
                }
            };
            self.note_origin(desk, &reply).await;
            if reply.tool_calls.is_empty() {
                self.answer(desk.steps, reply.content).await;
                return;
            }
            self.run_calls(desk, &mut thread, reply).await;
        }
        self.status(format!(
            "{} reached the step cap ({}) and stopped",
            self.name(),
            self.shared.max_steps
        ))
        .await;
    }

    /// Swap the system prompt if the commander toggled guardrails since the last step.
    async fn follow_guardrails(&self, thread: &mut Thread) {
        let guardrails = self.shared.guardrails();
        if guardrails == thread.guardrails {
            return;
        }
        thread.guardrails = guardrails;
        if let Some(system) = thread.messages.first_mut() {
            *system = Message::System {
                content: roles::system_prompt(self.role, guardrails),
            };
        }
        let prompt = if guardrails { "hardened" } else { "naive" };
        self.status(format!("{} switched to the {prompt} prompt", self.name()))
            .await;
    }

    /// The route for the next call; announces it when it changes.
    async fn route(&self, desk: &mut Desk, thread: &Thread) -> ModelRoute {
        let local = self.shared.router.local_model();
        let route = if thread.sensitive && local.is_some() {
            ModelRoute::Local
        } else {
            ModelRoute::Hosted
        };
        if desk.route != Some(route) {
            desk.route = Some(route);
            let reason = match (route, local) {
                (ModelRoute::Local, Some(model)) => {
                    format!(
                        "{}: sensitive evidence in context, local {model}",
                        self.name()
                    )
                }
                (ModelRoute::Local | ModelRoute::Hosted, _) => format!(
                    "{}: no sensitive evidence in context, hosted {} at {}",
                    self.name(),
                    self.shared.router.hosted_model(self.role),
                    self.shared.router.hosted_url()
                ),
            };
            self.publish(BusBody::Route { route, reason }).await;
        }
        route
    }

    /// Label replayed responses once per desk when the recording no longer matches exactly.
    async fn note_origin(&self, desk: &mut Desk, reply: &Reply) {
        if reply.origin == Origin::Replayed(Hit::Sequence) && !desk.replay_noted {
            desk.replay_noted = true;
            self.status(format!(
                "{}: this run's requests differ from the recording; replaying recorded {} responses in order",
                self.name(),
                reply.model
            ))
            .await;
        }
    }

    /// Publish the final answer as a trace step and a chat message.
    async fn answer(&self, step: u32, content: Option<String>) {
        let answer = content.unwrap_or_default();
        self.trace(
            step,
            "answer",
            Value::Object(Map::new()),
            preview(&answer, PREVIEW_CHARS),
        )
        .await;
        if !answer.is_empty() {
            self.publish(BusBody::Chat {
                text: clip(answer, 1_500),
            })
            .await;
        }
    }

    /// Check, record and run every tool call of one reply.
    async fn run_calls(&self, desk: &mut Desk, thread: &mut Thread, reply: Reply) {
        let mut history = Vec::with_capacity(reply.tool_calls.len());
        let mut outcomes = Vec::with_capacity(reply.tool_calls.len());
        for call in &reply.tool_calls {
            let Prepared {
                history_arguments,
                outcome,
            } = tools::prepare(self.tools(thread.guardrails), &call.name, &call.arguments);
            history.push(ToolCall::new(
                call.id.clone(),
                call.name.clone(),
                history_arguments,
            ));
            outcomes.push(outcome);
        }
        thread.messages.push(Message::Assistant {
            content: reply.content,
            tool_calls: history,
        });
        for (call, outcome) in reply.tool_calls.into_iter().zip(outcomes) {
            let content = self.run_call(desk, thread, &call.name, outcome).await;
            thread.messages.push(Message::Tool {
                tool_call_id: call.id,
                content,
            });
        }
    }

    /// Run one checked call; returns what the model reads back.
    async fn run_call(
        &self,
        desk: &mut Desk,
        thread: &mut Thread,
        name: &str,
        outcome: Result<Call, Rejection>,
    ) -> String {
        let Call { tool, args, action } = match outcome {
            Ok(call) => call,
            Err(Rejection { args, reason }) => {
                self.trace(desk.steps, name, args, preview(&reason, PREVIEW_CHARS))
                    .await;
                return format!("error: {reason}. Fix the call and try again.");
            }
        };
        let mut subject = None;
        let done = match action {
            Action::Exec(spec) => {
                subject = Some(format!("{} {}", tool.name(), spec.subject()));
                self.exec(spec).await
            }
            Action::RequestTool(ask) => self.request_tool(desk, ask).await,
            Action::Finding(finding) => self.report(desk, finding).await,
            Action::Proposal(proposal) => self.propose(desk, proposal).await,
            Action::Scope(update) => self.scope(desk, update).await,
            Action::Incident(update) => self.incident(desk, update).await,
        };
        self.trace(desk.steps, tool.name(), args, done.preview)
            .await;
        match subject {
            Some(subject) if done.untrusted => self.screen(desk, thread, &subject, done.text).await,
            Some(_) | None => done.text,
        }
    }

    /// Run a command in the role's stratum.
    async fn exec(&self, spec: ExecSpec) -> Done {
        let wait = Duration::from_millis(spec.timeout_ms) + EXEC_GRACE;
        let request = CoreRequest::Exec(ExecRequest {
            from: self.role,
            stratum: roles::stratum(self.role).to_owned(),
            argv: spec.argv,
            timeout_ms: spec.timeout_ms,
        });
        match self.conn.request(request, wait).await {
            Ok(CoreResponse::Exec(result)) => self.observe(&result).await,
            Ok(CoreResponse::Error { message }) => Done::error(&format!("cleanroomd: {message}")),
            Ok(other) => Done::error(&format!(
                "cleanroomd answered exec with `{}`",
                response_kind(&other)
            )),
            Err(error) => Done::error(&format!("{error:#}")),
        }
    }

    /// Turn an exec result into model text and a trace preview; count grant denials.
    async fn observe(&self, result: &ExecResult) -> Done {
        match &result.outcome {
            ExecOutcome::Denied { reason } => {
                self.shared.counters.denied_by_os();
                self.counters_status().await;
                Done {
                    text: format!(
                        "denied by the stratum grant: {reason}. The command did not run."
                    ),
                    preview: preview(&format!("denied: {reason}"), PREVIEW_CHARS),
                    untrusted: false,
                }
            }
            ExecOutcome::Exited { code } => Done {
                text: exec_text(&format!("exit code {code}"), result),
                preview: preview(
                    &format!("exit {code}: {}", first_output(result)),
                    PREVIEW_CHARS,
                ),
                untrusted: true,
            },
            ExecOutcome::TimedOut => Done {
                text: exec_text("timed out; partial output follows", result),
                preview: preview(
                    &format!("timed out: {}", first_output(result)),
                    PREVIEW_CHARS,
                ),
                untrusted: true,
            },
        }
    }

    /// Sensitivity routing and safety layer 1 for evidence-bearing output.
    async fn screen(
        &self,
        desk: &mut Desk,
        thread: &mut Thread,
        subject: &str,
        text: String,
    ) -> String {
        self.check_sensitive(desk, thread, &text).await;
        let route = if thread.sensitive && self.shared.router.local_model().is_some() {
            ModelRoute::Local
        } else {
            ModelRoute::Hosted
        };
        let artifact = format!("{}:{subject}", self.name());
        match self.shared.router.screen(self.role, route, &text).await {
            Ok((verdict, model)) => {
                let rating = format!("unsafe: {}", verdict.categories.join(", "));
                let safe = verdict.safe;
                self.publish(BusBody::SafetyVerdict {
                    artifact: artifact.clone(),
                    model,
                    safe,
                    categories: verdict.categories,
                })
                .await;
                if safe {
                    return text;
                }
                self.shared.counters.flagged(thread.guardrails);
                self.counters_status().await;
                if thread.guardrails {
                    safety::envelope(&artifact, &rating, &text)
                } else {
                    text
                }
            }
            Err(error) => {
                self.status(format!(
                    "{}: no safety verdict for {artifact} ({error:#}); treating the output as untrusted",
                    self.name()
                ))
                .await;
                if thread.guardrails {
                    safety::envelope(&artifact, "unscored", &text)
                } else {
                    text
                }
            }
        }
    }

    /// Flag personal data or credentials in `text` and publish the routing decision.
    async fn check_sensitive(&self, desk: &mut Desk, thread: &mut Thread, text: &str) {
        let hits = self.shared.detector.scan(text);
        if hits.is_empty() {
            return;
        }
        thread.sensitive = true;
        let found = sensitivity::describe(&hits);
        let (route, reason) = self.shared.router.local_model().map_or_else(
            || {
                (
                    ModelRoute::Hosted,
                    format!(
                        "{} saw {found}; no local endpoint is configured (CLEANROOM_LOCAL_BASE_URL), so it stays on hosted {}",
                        self.name(),
                        self.shared.router.hosted_model(self.role)
                    ),
                )
            },
            |model| {
                (
                    ModelRoute::Local,
                    format!("{} saw {found}; this conversation now runs on local {model}", self.name()),
                )
            },
        );
        desk.route = Some(route);
        self.publish(BusBody::Route { route, reason }).await;
    }

    /// Ask the daemon to admit a tool; wait for the commander if the request is pending.
    async fn request_tool(&self, desk: &mut Desk, ask: ToolAsk) -> Done {
        desk.tool_requests += 1;
        let id = format!(
            "{}-{}-tool-{}",
            desk.case.incident_id,
            self.name(),
            desk.tool_requests
        );
        let flake_ref = format!("{}#{}", self.shared.nixpkgs, ask.tool);
        let request = ToolRequest {
            id: id.clone(),
            from: self.role,
            stratum: roles::stratum(self.role).to_owned(),
            tool: ask.tool.clone(),
            source: ToolSource::Nix { flake_ref },
            reason: ask.reason,
        };
        let mut decisions = self.shared.control.subscribe();
        self.publish(BusBody::ToolRequest(request.clone())).await;
        let decision = match self
            .conn
            .request(CoreRequest::RequestTool(request), TOOL_REQUEST_WAIT)
            .await
        {
            Ok(CoreResponse::Tool {
                decision: ToolDecision::Pending,
                ..
            }) => wait_for_decision(&mut decisions, &id).await,
            Ok(CoreResponse::Tool { decision, .. }) => Some(decision),
            Ok(CoreResponse::Error { message }) => {
                return Done::error(&format!("cleanroomd: {message}"));
            }
            Ok(other) => {
                return Done::error(&format!(
                    "cleanroomd answered request_tool with `{}`",
                    response_kind(&other)
                ));
            }
            Err(error) => return Done::error(&format!("{error:#}")),
        };
        Done::ok(describe_decision(&ask.tool, decision))
    }

    /// Publish a finding and send it to Scribe.
    async fn report(&self, desk: &mut Desk, finding: FindingArgs) -> Done {
        let body = BusBody::Finding {
            summary: finding.summary.clone(),
            evidence: finding.evidence.clone(),
            confidence_pct: finding.confidence_pct,
        };
        if let Err(error) = self.conn.publish(body).await {
            return Done::error(&format!("cannot publish the finding: {error:#}"));
        }
        let text = format!(
            "finding published ({}% confidence) and sent to Scribe: {}",
            finding.confidence_pct,
            preview(&finding.summary, 120)
        );
        desk.forward(Note::Finding {
            from: self.role,
            finding: finding.clone(),
        });
        desk.findings.push(finding);
        Done::ok(text)
    }

    /// Publish a containment proposal and send it to Scribe.
    async fn propose(&self, desk: &mut Desk, proposal: ProposalArgs) -> Done {
        let proposal_id = format!(
            "{}-proposal-{}",
            desk.case.incident_id,
            desk.proposals.len() + 1
        );
        let body = BusBody::Proposal {
            proposal_id: proposal_id.clone(),
            action: proposal.action.clone(),
            rationale: proposal.rationale.clone(),
        };
        if let Err(error) = self.conn.publish(body).await {
            return Done::error(&format!("cannot publish the proposal: {error:#}"));
        }
        desk.proposals
            .push((proposal_id.clone(), proposal.action.clone()));
        let text = format!(
            "proposal {proposal_id} published; it takes effect only if the commander approves it"
        );
        desk.forward(Note::Proposal {
            proposal_id,
            proposal,
        });
        Done::ok(text)
    }

    /// Apply a scope update and publish the full record.
    async fn scope(&self, desk: &mut Desk, update: ScopeUpdate) -> Done {
        match desk.records.apply_scope(update, &now()) {
            Ok((record, summary)) => match self.conn.publish(BusBody::Scope(record)).await {
                Ok(()) => Done::ok(summary),
                Err(error) => Done::error(&format!("cannot publish the scope record: {error:#}")),
            },
            Err(reason) => Done::error(&reason),
        }
    }

    /// Apply an incident update and publish the full record.
    async fn incident(&self, desk: &mut Desk, update: IncidentUpdate) -> Done {
        match desk.records.apply_incident(&desk.case, update, &now()) {
            Ok((record, summary)) => match self.conn.publish(BusBody::Incident(record)).await {
                Ok(()) => Done::ok(summary),
                Err(error) => {
                    Done::error(&format!("cannot publish the incident record: {error:#}"))
                }
            },
            Err(reason) => Done::error(&reason),
        }
    }

    /// Publish a trace step and log it.
    async fn trace(&self, step: u32, tool: &str, args: Value, result_preview: String) {
        tracing::info!(role = self.name(), step, tool, "{result_preview}");
        self.publish(BusBody::Trace {
            step,
            tool: tool.to_owned(),
            args,
            result_preview,
        })
        .await;
    }

    /// Publish a status line (labelled in replay mode).
    pub(crate) async fn status(&self, text: String) {
        tracing::info!(role = self.name(), "{text}");
        self.publish(BusBody::Status {
            text: self.shared.label(text),
        })
        .await;
    }

    /// Publish the counters status line.
    pub(crate) async fn counters_status(&self) {
        self.publish(BusBody::Status {
            text: self.shared.counters_line(),
        })
        .await;
    }

    /// Publish, logging instead of failing: the bus is best effort for the loop itself.
    async fn publish(&self, body: BusBody) {
        if let Err(error) = self.conn.publish(body).await {
            tracing::warn!(
                role = self.name(),
                "cannot publish to cleanroomd: {error:#}"
            );
        }
    }

    /// The role name.
    const fn name(&self) -> &'static str {
        roles::name(self.role)
    }
}

/// Wait for the commander's decision on a pending tool request.
async fn wait_for_decision(
    decisions: &mut broadcast::Receiver<Control>,
    request_id: &str,
) -> Option<ToolDecision> {
    let deadline = tokio::time::Instant::now() + TOOL_DECISION_WAIT;
    loop {
        match tokio::time::timeout_at(deadline, decisions.recv()).await {
            Ok(Ok(Control::ToolDecision {
                request_id: decided,
                decision,
            })) if decided == request_id => return Some(decision),
            Ok(
                Ok(Control::ToolDecision { .. } | Control::Approval { .. })
                | Err(RecvError::Lagged(_)),
            ) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// What a tool decision means for the model.
fn describe_decision(tool: &str, decision: Option<ToolDecision>) -> String {
    match decision {
        Some(ToolDecision::AutoAllowed { rule }) => {
            format!("granted by policy rule `{rule}`: {tool} is now available in your stratum")
        }
        Some(ToolDecision::Approved { approver }) => {
            format!(
                "approved by the commander ({approver}): {tool} is now available in your stratum"
            )
        }
        Some(ToolDecision::Denied { reason }) => format!("request for {tool} refused: {reason}"),
        Some(ToolDecision::Pending) | None => format!(
            "request for {tool} is still pending with the commander after {} s; continue without it",
            TOOL_DECISION_WAIT.as_secs()
        ),
    }
}

/// Exec output as the model sees it, clipped.
fn exec_text(head: &str, result: &ExecResult) -> String {
    let mut text =
        String::with_capacity(head.len() + result.stdout.len() + result.stderr.len() + 48);
    text.push_str(head);
    if !result.stdout.is_empty() {
        text.push('\n');
        text.push_str(&result.stdout);
    }
    if !result.stderr.is_empty() {
        text.push_str("\n[stderr]\n");
        text.push_str(&result.stderr);
    }
    if result.truncated {
        text.push_str("\n[output truncated by cleanroomd]");
    }
    clip(text, MODEL_TEXT_LIMIT)
}

/// The first non-empty output stream, for previews.
fn first_output(result: &ExecResult) -> &str {
    if result.stdout.trim().is_empty() {
        &result.stderr
    } else {
        &result.stdout
    }
}

/// The variant name of a daemon response, for errors.
const fn response_kind(response: &CoreResponse) -> &'static str {
    match response {
        CoreResponse::Exec(_) => "exec",
        CoreResponse::Tool { .. } => "tool",
        CoreResponse::Admitted { .. } => "admitted",
        CoreResponse::AdmitRejected { .. } => "admit_rejected",
        CoreResponse::LogVerified { .. } => "log_verified",
        CoreResponse::Ok => "ok",
        CoreResponse::Error { .. } => "error",
    }
}
