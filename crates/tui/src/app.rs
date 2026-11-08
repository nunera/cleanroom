//! The controller: keys become signed requests and publishes; frames become state.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use cleanroom_proto::sign::{self, key_id};
use cleanroom_proto::{
    ApprovalDecision, Audience, BusBody, BusMessage, CoreRequest, CoreResponse, Envelope, Frame,
    KeyId, Principal, Role, WIRE_VERSION, domain,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use ratatui::{DefaultTerminal, Frame as TerminalFrame};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::MissedTickBehavior;
use tokio_stream::StreamExt as _;

use crate::replay;
use crate::state::{SentRequest, State, Tone};
use crate::ui::{self, Link, Overlay, View};

/// Redraw often enough that second-resolution countdowns tick smoothly.
const TICK: Duration = Duration::from_millis(250);
/// Shown when a key would talk to cleanroomd during a replay.
const REPLAY_ONLY: &str = "Replay: this console is playing a recording, so nothing was sent.";

/// Something for the controller from a background task.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A frame from cleanroomd or the recording (boxed: envelopes are large).
    Frame(Box<Envelope>),
    /// A line that is not an envelope.
    Malformed(String),
    /// The live connection ended.
    Closed(String),
    /// The recording has played to the end.
    ReplayDone,
    /// Writing the `--record` file failed; recording stopped.
    RecordFailed(String),
}

impl Inbound {
    /// Parse one NDJSON line from cleanroomd.
    pub(crate) fn parse(line: &str) -> Self {
        match serde_json::from_str(line) {
            Ok(envelope) => Self::Frame(Box::new(envelope)),
            Err(error) => Self::Malformed(error.to_string()),
        }
    }
}

/// The first frame: this console's human principal, its key, and every audience.
pub(crate) fn hello(key: &SigningKey) -> Envelope {
    let public = key.verifying_key();
    let roles = [
        Role::Hunter,
        Role::Forensics,
        Role::Scribe,
        Role::Containment,
    ];
    let subscribe = [Audience::All, Audience::Humans]
        .into_iter()
        .chain(roles.map(|role| Audience::Role { role }))
        .collect();
    Envelope {
        v: WIRE_VERSION,
        frame: Frame::Hello {
            principal: Principal::Human {
                key_id: key_id(&public),
            },
            public_key: hex::encode(public.as_bytes()),
            subscribe,
        },
    }
}

/// The live connection: the commander key, the outbound queue and requests awaiting answers.
#[derive(Debug)]
pub(crate) struct Session {
    /// Signs publishes and approvals.
    key: SigningKey,
    /// `sha256:` of the public key.
    key_id: KeyId,
    /// Frames for the writer task.
    outbound: UnboundedSender<Envelope>,
    /// Next request id.
    next_request: u64,
    /// Requests sent and not yet answered, by id.
    pending: HashMap<u64, SentRequest>,
    /// Bus message ids are `<prefix>-<n>`, unique per console run.
    message_prefix: String,
    /// Next bus message number.
    next_message: u64,
}

impl Session {
    /// A session that signs with `key` and writes to `outbound`.
    pub(crate) fn new(key: SigningKey, outbound: UnboundedSender<Envelope>) -> Self {
        let key_id = key_id(&key.verifying_key());
        let message_prefix = format!(
            "tui-{}-{}",
            crate::state::short_key(&key_id),
            Timestamp::now().as_millisecond()
        );
        Self {
            key,
            key_id,
            outbound,
            next_request: 1,
            pending: HashMap::new(),
            message_prefix,
            next_message: 1,
        }
    }

    /// Queue a frame for the writer task; false when the writer has stopped.
    fn send(&self, frame: Frame) -> bool {
        self.outbound
            .send(Envelope {
                v: WIRE_VERSION,
                frame,
            })
            .is_ok()
    }

    /// A fresh bus message id.
    fn message_id(&mut self) -> String {
        let id = format!("{}-{}", self.message_prefix, self.next_message);
        self.next_message += 1;
        id
    }
}

/// Where "now" comes from: the wall clock live, or the recording's own timeline in replay, so
/// legal clocks count down the way they did when the recording was made.
#[derive(Debug)]
enum Timebase {
    /// Wall clock.
    Live,
    /// Recording time: `anchor` at the real instant `since`, advancing at `speed`.
    Replay {
        /// Recording time at `since`.
        anchor: Timestamp,
        /// When `anchor` was set.
        since: Instant,
        /// Playback speed multiplier.
        speed: f64,
    },
}

impl Timebase {
    /// The current time on this timebase.
    fn now(&self) -> Timestamp {
        match self {
            Self::Live => Timestamp::now(),
            Self::Replay {
                anchor,
                since,
                speed,
            } => {
                let elapsed =
                    SignedDuration::try_from_secs_f64(since.elapsed().as_secs_f64() * speed)
                        .unwrap_or(SignedDuration::ZERO);
                anchor.checked_add(elapsed).unwrap_or(*anchor)
            }
        }
    }

    /// A frame stamped `at` just played: move recording time there, never backwards.
    fn arrived(&mut self, at: Timestamp) {
        let now = self.now();
        if let Self::Replay { anchor, since, .. } = self {
            *anchor = now.max(at);
            *since = Instant::now();
        }
    }
}

/// The keys the console reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    /// A printable character.
    Char(char),
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Enter.
    Enter,
    /// Escape.
    Esc,
    /// Backspace.
    Backspace,
}

/// The console's controller.
#[derive(Debug)]
pub(crate) struct App {
    /// Everything built from daemon frames.
    state: State,
    /// Selection, modals and typing.
    view: View,
    /// The live connection; `None` in replay.
    session: Option<Session>,
    /// Source of "now".
    timebase: Timebase,
    /// Root that `t` tampers with and that `A` admits again.
    tamper_root: String,
    /// False once the commander quits.
    running: bool,
}

impl App {
    /// A console connected through `session`.
    pub(crate) fn live(
        mut state: State,
        view: View,
        session: Session,
        tamper_root: String,
    ) -> Self {
        state.set_identity(session.key_id.clone());
        Self {
            state,
            view,
            session: Some(session),
            timebase: Timebase::Live,
            tamper_root,
            running: true,
        }
    }

    /// A console playing a recording that starts at `start`, at `speed`.
    pub(crate) fn replay(state: State, view: View, start: Timestamp, speed: f64) -> Self {
        Self {
            state,
            view,
            session: None,
            timebase: Timebase::Replay {
                anchor: start,
                since: Instant::now(),
                speed,
            },
            tamper_root: String::new(),
            running: true,
        }
    }

    /// Draw the console.
    fn draw(&self, frame: &mut TerminalFrame<'_>) {
        ui::render(frame, &self.state, &self.view, self.timebase.now());
    }

    /// Handle a message from a background task.
    fn on_inbound(&mut self, inbound: Inbound) {
        match inbound {
            Inbound::Frame(envelope) => self.on_frame(*envelope),
            Inbound::Malformed(error) => self
                .state
                .notify(Tone::Warn, format!("Ignored a malformed frame: {error}")),
            Inbound::Closed(reason) => self.view.link = Link::Live { down: Some(reason) },
            Inbound::ReplayDone => {
                if let Link::Replay { finished, .. } = &mut self.view.link {
                    *finished = true;
                }
            }
            Inbound::RecordFailed(error) => self
                .state
                .notify(Tone::Bad, format!("Recording stopped: {error}")),
        }
    }

    /// Fold a frame into state, and re-admit after a successful tamper.
    fn on_frame(&mut self, envelope: Envelope) {
        if let Some(at) = replay::stamp(&envelope) {
            self.timebase.arrived(at);
        }
        let sent = match &envelope.frame {
            Frame::Response { id, .. } => self
                .session
                .as_mut()
                .and_then(|session| session.pending.remove(id)),
            Frame::Hello { .. } | Frame::Publish(_) | Frame::Event(_) | Frame::Request { .. } => {
                None
            }
        };
        let readmit = if let (
            Some(SentRequest::Tamper { root }),
            Frame::Response {
                response: CoreResponse::Ok,
                ..
            },
        ) = (&sent, &envelope.frame)
        {
            Some(root.clone())
        } else {
            None
        };
        let now = self.timebase.now();
        self.state.apply(envelope, sent.as_ref(), now);
        self.view.selected = self
            .view
            .selected
            .min(self.state.queue.len().saturating_sub(1));
        if let Some(root) = readmit {
            self.request(
                CoreRequest::Admit { root: root.clone() },
                SentRequest::Admit { root },
            );
        }
    }

    /// Handle a terminal event.
    fn on_terminal(&mut self, event: &Event) {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => self.on_key(*key),
            Event::Key(_)
            | Event::FocusGained
            | Event::FocusLost
            | Event::Mouse(_)
            | Event::Paste(_)
            | Event::Resize(..) => {}
        }
    }

    /// Route a key press to the chat line, the open modal, or the command keys.
    fn on_key(&mut self, event: KeyEvent) {
        if event.modifiers.contains(KeyModifiers::CONTROL) && event.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }
        let Some(key) = key(event.code) else {
            return;
        };
        if self.view.chat.is_some() {
            self.on_chat_key(key);
        } else if key == Key::Char('q') {
            self.running = false;
        } else if self.view.admission_visible(&self.state) {
            if matches!(key, Key::Enter | Key::Esc | Key::Char(' ')) {
                self.view.admission_seen = self.state.admission_seq;
            }
        } else {
            match self.view.overlay {
                Overlay::None => self.on_command_key(key),
                Overlay::Help => {
                    if matches!(key, Key::Esc | Key::Enter | Key::Char('?')) {
                        self.view.overlay = Overlay::None;
                    }
                }
                Overlay::Detonate { cursor } => self.on_picker_key(key, cursor),
                Overlay::ConfirmReset => self.on_confirm_key(key),
            }
        }
    }

    /// A key with no modal open.
    fn on_command_key(&mut self, key: Key) {
        match key {
            Key::Char('?') => self.view.overlay = Overlay::Help,
            Key::Char('d') => self.open_detonate(),
            Key::Char('t') => {
                let root = self.tamper_root.clone();
                self.request(
                    CoreRequest::Tamper { root: root.clone() },
                    SentRequest::Tamper { root },
                );
            }
            // Shift+A: after a rejection cleanroomd discards the tampered copy, so this admission
            // checks a clean one.
            Key::Char('A') => {
                let root = self.tamper_root.clone();
                self.request(
                    CoreRequest::Admit { root: root.clone() },
                    SentRequest::Admit { root },
                );
            }
            Key::Char('a') => self.decide(true),
            Key::Char('x') => self.decide(false),
            Key::Char('g') => self.publish(BusBody::AgentControl {
                guardrails: !self.state.guardrails,
            }),
            Key::Char('i') => self.investigate(),
            Key::Char('v') => self.request(CoreRequest::VerifyLog, SentRequest::VerifyLog),
            Key::Char('r') => self.view.overlay = Overlay::ConfirmReset,
            Key::Char('c' | '/') => self.view.chat = Some(String::new()),
            Key::Up | Key::Char('k') => self.view.selected = self.view.selected.saturating_sub(1),
            Key::Down | Key::Char('j') => {
                let last = self.state.queue.len().saturating_sub(1);
                self.view.selected = (self.view.selected + 1).min(last);
            }
            Key::Char(_) | Key::Enter | Key::Esc | Key::Backspace => {}
        }
    }

    /// Typing a chat message.
    fn on_chat_key(&mut self, key: Key) {
        match key {
            Key::Char(typed) => {
                if let Some(text) = self.view.chat.as_mut() {
                    text.push(typed);
                }
            }
            Key::Backspace => {
                if let Some(text) = self.view.chat.as_mut() {
                    text.pop();
                }
            }
            Key::Esc => self.view.chat = None,
            Key::Enter => {
                let text = self.view.chat.take().unwrap_or_default();
                let text = text.trim();
                if !text.is_empty() {
                    self.publish(BusBody::Chat {
                        text: text.to_owned(),
                    });
                }
            }
            Key::Up | Key::Down => {}
        }
    }

    /// The scenario picker.
    fn on_picker_key(&mut self, key: Key, cursor: usize) {
        let last = self.view.scenarios.len().saturating_sub(1);
        match key {
            Key::Up => {
                self.view.overlay = Overlay::Detonate {
                    cursor: cursor.saturating_sub(1),
                }
            }
            Key::Down => {
                self.view.overlay = Overlay::Detonate {
                    cursor: (cursor + 1).min(last),
                }
            }
            Key::Enter => {
                self.view.overlay = Overlay::None;
                if let Some(scenario) = self.view.scenarios.get(cursor).cloned() {
                    self.request(
                        CoreRequest::Detonate {
                            scenario: scenario.clone(),
                        },
                        SentRequest::Detonate { scenario },
                    );
                }
            }
            Key::Esc => self.view.overlay = Overlay::None,
            Key::Char(_) | Key::Backspace => {}
        }
    }

    /// The reset confirmation.
    fn on_confirm_key(&mut self, key: Key) {
        match key {
            Key::Char('y' | 'Y') | Key::Enter => {
                self.view.overlay = Overlay::None;
                self.request(CoreRequest::Reset, SentRequest::Reset);
            }
            Key::Char('n' | 'N') | Key::Esc => self.view.overlay = Overlay::None,
            Key::Char(_) | Key::Up | Key::Down | Key::Backspace => {}
        }
    }

    /// Open the scenario picker.
    fn open_detonate(&mut self) {
        if self.session.is_none() {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
        } else if self.view.scenarios.is_empty() {
            self.state
                .notify(Tone::Warn, "No scenarios configured; pass --scenario NAME.");
        } else {
            self.view.overlay = Overlay::Detonate { cursor: 0 };
        }
    }

    /// Sign an approve or deny decision for the selected queue item and send it.
    fn decide(&mut self, approved: bool) {
        let Some(item) = self.state.queue.get(self.view.selected) else {
            self.state
                .notify(Tone::Quiet, "Nothing is waiting for your signature.");
            return;
        };
        if item.sent.is_some() {
            self.state.notify(
                Tone::Quiet,
                "Already decided; waiting for cleanroomd to confirm.",
            );
            return;
        }
        let subject_id = item.subject_id.clone();
        let Some(session) = &self.session else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return;
        };
        let decision = ApprovalDecision {
            subject_id: subject_id.clone(),
            approved,
            at: now_text(),
        };
        match sign::sign(&session.key, domain::APPROVAL, decision) {
            Ok(signed) => self.request(
                CoreRequest::Approve(signed),
                SentRequest::Decide {
                    subject_id,
                    approved,
                },
            ),
            Err(error) => self
                .state
                .notify(Tone::Bad, format!("Could not sign the decision: {error}")),
        }
    }

    /// Start the agent team on the current incident.
    fn investigate(&mut self) {
        let Some(incident) = &self.state.incident else {
            self.state.notify(
                Tone::Warn,
                "No incident yet. Detonate a scenario first (d).",
            );
            return;
        };
        let brief = if incident.summary.is_empty() {
            incident.title.clone()
        } else {
            incident.summary.clone()
        };
        let incident_id = incident.id.clone();
        self.publish(BusBody::Investigate { incident_id, brief });
    }

    /// Send a daemon request and remember it until its response arrives.
    fn request(&mut self, request: CoreRequest, sent: SentRequest) {
        if !self.view.connected() {
            self.state
                .notify(Tone::Bad, "Not connected to cleanroomd; nothing was sent.");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return;
        };
        let id = session.next_request;
        session.next_request += 1;
        let what = sent.describe();
        session.pending.insert(id, sent);
        if session.send(Frame::Request { id, request }) {
            self.state.notify(
                Tone::Quiet,
                format!("{what}: sent, waiting for cleanroomd…"),
            );
        } else {
            self.view.link = Link::Live {
                down: Some("the connection writer stopped".to_owned()),
            };
        }
    }

    /// Sign and publish a bus message from the commander. It shows up when cleanroomd echoes it.
    fn publish(&mut self, body: BusBody) {
        if !self.view.connected() {
            self.state
                .notify(Tone::Bad, "Not connected to cleanroomd; nothing was sent.");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return;
        };
        let message = BusMessage {
            id: session.message_id(),
            at: now_text(),
            from: Principal::Human {
                key_id: session.key_id.clone(),
            },
            to: Audience::All,
            body,
        };
        match sign::sign(&session.key, domain::BUS, message) {
            Ok(signed) => {
                if !session.send(Frame::Publish(signed)) {
                    self.view.link = Link::Live {
                        down: Some("the connection writer stopped".to_owned()),
                    };
                }
            }
            Err(error) => self
                .state
                .notify(Tone::Bad, format!("Could not sign the message: {error}")),
        }
    }
}

/// Map a crossterm key code to a [`Key`]; every other key does nothing in this console.
#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "crossterm's KeyCode has two dozen variants and every unlisted key is deliberately \
              ignored. `allow`, not `expect`: the lint only runs under the strict profile"
)]
const fn key(code: KeyCode) -> Option<Key> {
    match code {
        KeyCode::Char(typed) => Some(Key::Char(typed)),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Esc),
        KeyCode::Backspace => Some(Key::Backspace),
        _ => None,
    }
}

/// Now as an RFC 3339 UTC timestamp with whole seconds, for wire records.
fn now_text() -> String {
    let now = Timestamp::now();
    Timestamp::from_second(now.as_second())
        .unwrap_or(now)
        .to_string()
}

/// Run the console until the commander quits: draw, then wait for a key, a frame or a tick.
///
/// # Errors
/// Fails when the terminal can't be drawn to or its event stream fails.
pub(crate) async fn run(
    terminal: &mut DefaultTerminal,
    mut app: App,
    mut inbound: UnboundedReceiver<Inbound>,
) -> io::Result<()> {
    let mut keys = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut inbound_open = true;
    while app.running {
        terminal.draw(|frame| app.draw(frame))?;
        tokio::select! {
            event = keys.next() => match event {
                Some(Ok(event)) => app.on_terminal(&event),
                Some(Err(error)) => return Err(error),
                None => return Ok(()),
            },
            message = inbound.recv(), if inbound_open => match message {
                Some(message) => {
                    app.on_inbound(message);
                    while let Ok(more) = inbound.try_recv() {
                        app.on_inbound(more);
                    }
                }
                None => inbound_open = false,
            },
            _ = tick.tick() => {}
        }
    }
    Ok(())
}
