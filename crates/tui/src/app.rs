//! The controller: keys become signed requests and publishes; frames become state.
//!
//! Keys go to exactly one place. An open modal takes them first; otherwise the focus decides:
//! with the message line focused every printable key is text (Esc leaves it), and with command
//! focus the letters are commands. The Cleanroom screen opens with the message line focused.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use cleanroom_proto::sign::{self, key_id};
use cleanroom_proto::{
    ApprovalDecision, Audience, BusBody, BusMessage, CoreRequest, CoreResponse, Envelope, Frame,
    KeyId, Member, MemberRole, Principal, Revocation, Role, WIRE_VERSION, domain,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ed25519_dalek::SigningKey;
use jiff::{SignedDuration, Timestamp};
use ratatui::{DefaultTerminal, Frame as TerminalFrame};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_stream::StreamExt as _;

use crate::access::{MEMBER_ROLES, Standing};
use crate::motion::Motion;
use crate::replay;
use crate::state::{SentRequest, State, Tone};
use crate::team;
use crate::ui::{self, Field, Focus, Link, Overlay, Pane, Tab, View};

/// Redraw often enough that second-resolution countdowns tick smoothly.
const TICK: Duration = Duration::from_millis(250);
/// Redraw at about 30 fps while something moves.
const FRAME: Duration = Duration::from_millis(33);
/// Shown when a key would talk to cleanroomd during a replay.
const REPLAY_ONLY: &str = "Replay: this console is playing a recording, so nothing was sent.";
/// Conversation lines one PgUp/PgDn moves.
const PAGE: usize = 10;
/// Reason recorded when the commander revokes without typing one.
const DEFAULT_REVOKE_REASON: &str = "revoked by the commander";

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

/// The first frame: this console's human principal, its key, and every audience, the Lead's
/// included, so the whole conversation (and this console's own messages) comes back.
pub(crate) fn hello(key: &SigningKey) -> Envelope {
    let public = key.verifying_key();
    let roles = [
        Role::Lead,
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

/// Who a typed message is for: `@hunter …` (or any prefix, `@h …`) goes to that agent, anything
/// else to the Lead. Returns the role and the message without the address.
///
/// # Errors
/// Names no agent, or has nothing after the address.
pub(crate) fn address(text: &str) -> Result<(Role, &str), String> {
    let Some(rest) = text.strip_prefix('@') else {
        return Ok((Role::Lead, text));
    };
    let (name, message) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let role = team::mention(name).ok_or_else(|| {
        format!(
            "Nobody is called @{name}. Try @lead, @hunter, @forensics, @scribe or @containment."
        )
    })?;
    let message = message.trim();
    if message.is_empty() {
        return Err(format!(
            "Write the message after @{}.",
            team::title(role).to_lowercase()
        ));
    }
    Ok((role, message))
}

/// The live connection: the commander key, the outbound queue and requests awaiting answers.
#[derive(Debug)]
pub(crate) struct Session {
    /// Signs publishes, approvals, enrollments and revocations.
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
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// Enter.
    Enter,
    /// Escape.
    Esc,
    /// Backspace.
    Backspace,
    /// Tab.
    Tab,
    /// Shift+Tab.
    BackTab,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// End.
    End,
    /// A function key: F1 to F6 and F10 open tabs.
    F(u8),
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
    /// Effects over the frame; `None` when motion is off.
    motion: Option<Motion>,
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
        let motion = view.motion.then(|| Motion::new(&view));
        Self {
            state,
            view,
            session: Some(session),
            timebase: Timebase::Live,
            tamper_root,
            running: true,
            motion,
        }
    }

    /// A console playing a recording that starts at `start`, at `speed`.
    pub(crate) fn replay(state: State, view: View, start: Timestamp, speed: f64) -> Self {
        let motion = view.motion.then(|| Motion::new(&view));
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
            motion,
        }
    }

    /// Draw the console, then run the motion effects over the frame.
    fn draw(&mut self, frame: &mut TerminalFrame<'_>) {
        ui::render(frame, &self.state, &self.view, self.timebase.now());
        if let Some(motion) = &mut self.motion {
            motion.observe(&self.state, &self.view);
            let area = frame.area();
            motion.process(frame.buffer_mut(), area);
        }
    }

    /// How long to wait for the next frame: about 30 fps while something moves, else a tick.
    fn pause(&self) -> Duration {
        if self.motion.as_ref().is_some_and(Motion::busy) {
            FRAME
        } else {
            TICK
        }
    }

    /// Move the focus to the next panel (`forward`) or the previous one.
    fn move_focus(&mut self, forward: bool) {
        let now = self.timebase.now();
        self.view.move_focus(&self.state, now, forward);
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

    /// Fold a frame into state, re-admit after a successful tamper, and clear the enroll form
    /// once cleanroomd accepted the enrollment.
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
        let accepted = matches!(
            &envelope.frame,
            Frame::Response {
                response: CoreResponse::Ok,
                ..
            }
        );
        let readmit = match &sent {
            Some(SentRequest::Tamper { root }) if accepted => Some(root.clone()),
            Some(_) | None => None,
        };
        let enrolled = accepted && matches!(sent, Some(SentRequest::Enroll { .. }));
        let now = self.timebase.now();
        self.state.apply(envelope, sent.as_ref(), now);
        self.view.selected = self
            .view
            .selected
            .min(self.state.queue.len().saturating_sub(1));
        if enrolled {
            self.view.access.key.clear();
            self.view.access.name.clear();
            self.view.access.field = Field::List;
        }
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
            Event::Paste(text) => self.on_paste(text),
            Event::Key(_)
            | Event::FocusGained
            | Event::FocusLost
            | Event::Mouse(_)
            | Event::Resize(..) => {}
        }
    }

    /// Pasted text goes to whatever text field has focus, one line of it.
    fn on_paste(&mut self, text: &str) {
        let line = text.lines().next().unwrap_or_default();
        if let Some(field) = self.text_field() {
            field.push_str(line);
        }
    }

    /// The text being typed right now, if any.
    fn text_field(&mut self) -> Option<&mut String> {
        if self.view.admission_visible(&self.state) {
            return None;
        }
        match self.view.overlay {
            Overlay::Members => {
                let form = &mut self.view.access;
                if let Some(reason) = form.reason.as_mut() {
                    return Some(reason);
                }
                match form.field {
                    Field::Key => Some(&mut form.key),
                    Field::Name => Some(&mut form.name),
                    Field::List | Field::Role => None,
                }
            }
            Overlay::None => (self.view.focus == Focus::Input).then_some(&mut self.view.draft),
            Overlay::Help | Overlay::Detonate { .. } | Overlay::ConfirmReset => None,
        }
    }

    /// Route a key press: modal first, then the screen switch, then the focus.
    fn on_key(&mut self, event: KeyEvent) {
        if event.modifiers.contains(KeyModifiers::CONTROL) && event.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }
        let Some(key) = key(event.code) else {
            return;
        };
        let typing = self.view.focus == Focus::Input && self.view.overlay == Overlay::None;
        if key == Key::Char('q') && !typing && self.view.overlay != Overlay::Members {
            self.running = false;
        } else if self.view.admission_visible(&self.state) {
            if matches!(key, Key::Enter | Key::Esc | Key::Char(' ')) {
                self.view.admission_seen = self.state.admission_seq;
            }
        } else {
            match self.view.overlay {
                Overlay::None => self.on_screen_key(key),
                Overlay::Help => {
                    if matches!(key, Key::Esc | Key::Enter | Key::Char('?')) {
                        self.view.overlay = Overlay::None;
                    }
                }
                Overlay::Detonate { cursor } => self.on_picker_key(key, cursor),
                Overlay::ConfirmReset => self.on_confirm_key(key),
                Overlay::Members => self.on_members_key(key),
            }
        }
    }

    /// A key with no modal open: tab switches work everywhere, the rest follows the focus.
    fn on_screen_key(&mut self, key: Key) {
        let talking = matches!(self.view.tab, Tab::Lead | Tab::Controlroom);
        match key {
            Key::Tab => self.view.show(self.view.tab.step(true)),
            Key::BackTab => self.view.show(self.view.tab.step(false)),
            Key::F(number) => {
                if let Some(tab) = Tab::for_key(number) {
                    self.view.show(tab);
                }
            }
            Key::PageUp if talking => self.scroll_by(PAGE, true),
            Key::PageDown if talking => self.scroll_by(PAGE, false),
            Key::End if talking => self.view.scroll = 0,
            Key::Char(_)
            | Key::Up
            | Key::Down
            | Key::Left
            | Key::Right
            | Key::Enter
            | Key::Esc
            | Key::Backspace
            | Key::PageUp
            | Key::PageDown
            | Key::End => match self.view.focus {
                Focus::Input => self.on_input_key(key),
                Focus::Keys => self.on_command_key(key),
            },
        }
    }

    /// Scroll the conversation back (`back`) or forward by `lines`.
    fn scroll_by(&mut self, lines: usize, back: bool) {
        let limit = self.view.scroll_limit.get();
        self.view.scroll = if back {
            self.view.scroll.saturating_add(lines).min(limit)
        } else {
            self.view.scroll.saturating_sub(lines)
        };
    }

    /// Typing in the message line: every printable key is text.
    fn on_input_key(&mut self, key: Key) {
        match key {
            Key::Char(typed) => self.view.draft.push(typed),
            Key::Backspace => {
                self.view.draft.pop();
            }
            Key::Enter => self.send_draft(),
            Key::Esc => self.view.focus = Focus::Keys,
            Key::Up
            | Key::Down
            | Key::Left
            | Key::Right
            | Key::Tab
            | Key::BackTab
            | Key::PageUp
            | Key::PageDown
            | Key::End
            | Key::F(_) => {}
        }
    }

    /// Send the draft to the Lead, or to the agent it names with `@`. The line keeps focus.
    fn send_draft(&mut self) {
        let text = self.view.draft.trim().to_owned();
        if text.is_empty() {
            return;
        }
        match address(&text) {
            Ok((role, message)) => {
                let body = BusBody::Chat {
                    text: message.to_owned(),
                };
                if self.publish(body, Audience::Role { role }) {
                    self.view.draft.clear();
                    self.view.scroll = 0;
                }
            }
            Err(problem) => self.state.notify(Tone::Warn, problem),
        }
    }

    /// A command key, with the message line unfocused.
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
            Key::Char('g') => {
                let body = BusBody::AgentControl {
                    guardrails: !self.state.guardrails,
                };
                self.publish(body, Audience::All);
            }
            Key::Char('i') => self.investigate(),
            Key::Char('v') => self.request(CoreRequest::VerifyLog, SentRequest::VerifyLog),
            Key::Char('r') => self.view.overlay = Overlay::ConfirmReset,
            Key::Char('m') => self.open_members(),
            Key::Char('c' | '/') => match self.view.tab {
                Tab::Lead | Tab::Controlroom => self.view.focus = Focus::Input,
                Tab::Overview
                | Tab::Scope
                | Tab::Record
                | Tab::Defense
                | Tab::Team
                | Tab::Memory => {
                    self.view.show(Tab::Lead);
                }
            },
            Key::Up | Key::Char('k') => self.select(true),
            Key::Down | Key::Char('j') => self.select(false),
            Key::Left | Key::Right if self.view.tab == Tab::Controlroom => {
                self.view.pane = self.view.pane.other();
            }
            Key::Left | Key::Char('[') => self.move_focus(false),
            Key::Right | Key::Char(']') => self.move_focus(true),
            Key::Char(',') => self.view.chart = self.view.chart.step(false),
            Key::Char('.') => self.view.chart = self.view.chart.step(true),
            Key::Enter => match (self.view.tab, self.view.pane) {
                (Tab::Lead, _) => self.view.focus = Focus::Input,
                (Tab::Controlroom, Pane::Trace) => {
                    self.view.trace = match self.view.trace {
                        Some(_) => None,
                        None => self.state.activity.len().checked_sub(1),
                    };
                }
                (
                    Tab::Controlroom
                    | Tab::Overview
                    | Tab::Scope
                    | Tab::Record
                    | Tab::Defense
                    | Tab::Team
                    | Tab::Memory,
                    _,
                ) => {}
            },
            Key::Esc => self.view.trace = None,
            Key::Char(_)
            | Key::Backspace
            | Key::Tab
            | Key::BackTab
            | Key::PageUp
            | Key::PageDown
            | Key::End
            | Key::F(_) => {}
        }
    }

    /// Move the selection up (`up`) or down: approvals, or a trace step in the Controlroom's
    /// trace pane. Stepping down past the newest step follows the trace again.
    fn select(&mut self, up: bool) {
        if self.view.tab == Tab::Controlroom && self.view.pane == Pane::Trace {
            let last = self.state.activity.len().checked_sub(1);
            self.view.trace = match (self.view.trace, up) {
                (None, true) => last,
                (None, false) => None,
                (Some(index), true) => Some(index.saturating_sub(1)),
                (Some(index), false) if Some(index) >= last => None,
                (Some(index), false) => Some(index + 1),
            };
            return;
        }
        let last = self.state.queue.len().saturating_sub(1);
        self.view.selected = if up {
            self.view.selected.saturating_sub(1)
        } else {
            (self.view.selected + 1).min(last)
        };
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
            Key::Char(_)
            | Key::Left
            | Key::Right
            | Key::Backspace
            | Key::Tab
            | Key::BackTab
            | Key::PageUp
            | Key::PageDown
            | Key::End
            | Key::F(_) => {}
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
            Key::Char(_)
            | Key::Up
            | Key::Down
            | Key::Left
            | Key::Right
            | Key::Backspace
            | Key::Tab
            | Key::BackTab
            | Key::PageUp
            | Key::PageDown
            | Key::End
            | Key::F(_) => {}
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

    /// Open access control with the member list focused.
    fn open_members(&mut self) {
        let rows = ui::listed_members(&self.state).len();
        let form = &mut self.view.access;
        form.field = Field::List;
        form.reason = None;
        form.selected = form.selected.min(rows);
        self.view.overlay = Overlay::Members;
    }

    /// A key in the access-control overlay.
    fn on_members_key(&mut self, key: Key) {
        if let Some(reason) = self.view.access.reason.as_mut() {
            match key {
                Key::Char(typed) => reason.push(typed),
                Key::Backspace => {
                    reason.pop();
                }
                Key::Enter => self.revoke_selected(),
                Key::Esc => self.view.access.reason = None,
                Key::Up
                | Key::Down
                | Key::Left
                | Key::Right
                | Key::Tab
                | Key::BackTab
                | Key::PageUp
                | Key::PageDown
                | Key::End
                | Key::F(_) => {}
            }
            return;
        }
        let field = self.view.access.field;
        match (field, key) {
            (_, Key::Esc) => self.view.overlay = Overlay::None,
            (_, Key::Tab) | (Field::Key | Field::Name | Field::Role, Key::Down) => {
                self.view.access.field = next_field(field, true);
            }
            (_, Key::BackTab) | (Field::Key | Field::Name | Field::Role, Key::Up) => {
                self.view.access.field = next_field(field, false);
            }
            (Field::List, Key::Up | Key::Char('k')) => {
                self.view.access.selected = self.view.access.selected.saturating_sub(1);
            }
            (Field::List, Key::Down | Key::Char('j')) => {
                let rows = ui::listed_members(&self.state).len();
                self.view.access.selected = (self.view.access.selected + 1).min(rows);
            }
            (Field::List, Key::Enter) => self.copy_member(),
            (Field::List, Key::Char('r')) => self.ask_revoke_reason(),
            (Field::Key, Key::Char(typed)) if !typed.is_whitespace() => {
                self.view.access.key.push(typed);
            }
            (Field::Name, Key::Char(typed)) => self.view.access.name.push(typed),
            (Field::Key, Key::Backspace) => {
                self.view.access.key.pop();
            }
            (Field::Name, Key::Backspace) => {
                self.view.access.name.pop();
            }
            (Field::Role, Key::Left | Key::Right | Key::Char(' ')) => {
                self.view.access.role = cycle_role(self.view.access.role, key != Key::Left);
            }
            (Field::Key | Field::Name | Field::Role, Key::Enter) => self.enroll(),
            (
                Field::List | Field::Key | Field::Name | Field::Role,
                Key::Char(_)
                | Key::Left
                | Key::Right
                | Key::Backspace
                | Key::PageUp
                | Key::PageDown
                | Key::End
                | Key::F(_),
            ) => {}
        }
    }

    /// Copy the selected row into the enroll form: this console's own key, or a member this
    /// console enrolled (to enroll a revoked key again).
    fn copy_member(&mut self) {
        let mine = self
            .session
            .as_ref()
            .map(|session| hex::encode(session.key.verifying_key().as_bytes()));
        let chosen = ui::selected_member(&self.state, &self.view.access).cloned();
        let nobody_enrolled = self
            .state
            .roster
            .all()
            .iter()
            .all(|member| member.standing == Standing::Revoked);
        let form = &mut self.view.access;
        let public_key = if form.selected == 0 {
            if nobody_enrolled {
                form.role = MemberRole::Admin;
            }
            mine
        } else {
            chosen.as_ref().and_then(|member| member.public_key.clone())
        };
        let Some(public_key) = public_key else {
            self.state.notify(
                Tone::Warn,
                "Only keys this console enrolled can be copied; paste the member's public key.",
            );
            return;
        };
        form.key = public_key;
        if let Some(member) = chosen {
            form.name = member.name.unwrap_or_default();
            form.role = member.role.unwrap_or(form.role);
        }
        form.field = if form.name.is_empty() {
            Field::Name
        } else {
            Field::Role
        };
    }

    /// Open the revoke prompt for the selected member, if it is enrolled.
    fn ask_revoke_reason(&mut self) {
        match ui::selected_member(&self.state, &self.view.access) {
            Some(member) if member.standing == Standing::Enrolled => {
                self.view.access.reason = Some(String::new());
            }
            Some(_) => self
                .state
                .notify(Tone::Quiet, "That key is already revoked."),
            None => self.state.notify(
                Tone::Warn,
                "Nothing to revoke: this console has not seen that key enrolled.",
            ),
        }
    }

    /// Sign an enrollment of the form's key, name and role, and send it.
    fn enroll(&mut self) {
        let public_key = self.view.access.key.trim().to_lowercase();
        let name = self.view.access.name.trim().to_owned();
        let role = self.view.access.role;
        let public = match sign::verifying_key_from_hex(&public_key) {
            Ok(public) => public,
            Err(error) => {
                self.state.notify(
                    Tone::Warn,
                    format!("Paste the member's Ed25519 public key as 64 hex digits ({error})."),
                );
                self.view.access.field = Field::Key;
                return;
            }
        };
        if name.is_empty() {
            self.state.notify(Tone::Warn, "Give the member a name.");
            self.view.access.field = Field::Name;
            return;
        }
        let Some(session) = &self.session else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return;
        };
        let member = Member {
            key_id: key_id(&public),
            public_key: public_key.clone(),
            name: name.clone(),
            role,
            enrolled_at: now_text(),
        };
        let key_id = member.key_id.clone();
        match sign::sign(&session.key, domain::ENROLL, member) {
            Ok(signed) => self.request(
                CoreRequest::Enroll(signed),
                SentRequest::Enroll {
                    key_id,
                    public_key,
                    name,
                    role,
                },
            ),
            Err(error) => self
                .state
                .notify(Tone::Bad, format!("Could not sign the enrollment: {error}")),
        }
    }

    /// Sign a revocation of the selected member with the typed reason, and send it.
    fn revoke_selected(&mut self) {
        let typed = self.view.access.reason.take().unwrap_or_default();
        let reason = match typed.trim() {
            "" => DEFAULT_REVOKE_REASON.to_owned(),
            typed => typed.to_owned(),
        };
        let Some(member) = ui::selected_member(&self.state, &self.view.access) else {
            return;
        };
        let (key_id, name) = (member.key_id.clone(), member.name.clone());
        let Some(session) = &self.session else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return;
        };
        let revocation = Revocation {
            key_id: key_id.clone(),
            reason,
            revoked_at: now_text(),
        };
        match sign::sign(&session.key, domain::REVOKE, revocation) {
            Ok(signed) => self.request(
                CoreRequest::Revoke(signed),
                SentRequest::Revoke { key_id, name },
            ),
            Err(error) => self
                .state
                .notify(Tone::Bad, format!("Could not sign the revocation: {error}")),
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
        self.publish(BusBody::Investigate { incident_id, brief }, Audience::All);
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

    /// Sign and publish a bus message from the commander to `to`; true when it was queued. It
    /// shows up when cleanroomd echoes it.
    fn publish(&mut self, body: BusBody, to: Audience) -> bool {
        if !self.view.connected() {
            self.state
                .notify(Tone::Bad, "Not connected to cleanroomd; nothing was sent.");
            return false;
        }
        let Some(session) = self.session.as_mut() else {
            self.state.notify(Tone::Warn, REPLAY_ONLY);
            return false;
        };
        let message = BusMessage {
            id: session.message_id(),
            at: now_text(),
            from: Principal::Human {
                key_id: session.key_id.clone(),
            },
            to,
            body,
        };
        match sign::sign(&session.key, domain::BUS, message) {
            Ok(signed) => {
                if session.send(Frame::Publish(signed)) {
                    return true;
                }
                self.view.link = Link::Live {
                    down: Some("the connection writer stopped".to_owned()),
                };
                false
            }
            Err(error) => {
                self.state
                    .notify(Tone::Bad, format!("Could not sign the message: {error}"));
                false
            }
        }
    }
}

/// The next (`forward`) or previous part of the access-control overlay.
const fn next_field(field: Field, forward: bool) -> Field {
    match (field, forward) {
        (Field::List, true) | (Field::Name, false) => Field::Key,
        (Field::Key, true) | (Field::Role, false) => Field::Name,
        (Field::Name, true) | (Field::List, false) => Field::Role,
        (Field::Role, true) | (Field::Key, false) => Field::List,
    }
}

/// The next (`forward`) or previous member role.
fn cycle_role(role: MemberRole, forward: bool) -> MemberRole {
    let index = MEMBER_ROLES
        .iter()
        .position(|candidate| *candidate == role)
        .unwrap_or(0);
    let count = MEMBER_ROLES.len();
    let next = if forward {
        (index + 1) % count
    } else {
        (index + count - 1) % count
    };
    MEMBER_ROLES.get(next).copied().unwrap_or(role)
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
        KeyCode::Left => Some(Key::Left),
        KeyCode::Right => Some(Key::Right),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Esc),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Tab => Some(Key::Tab),
        KeyCode::BackTab => Some(Key::BackTab),
        KeyCode::PageUp => Some(Key::PageUp),
        KeyCode::PageDown => Some(Key::PageDown),
        KeyCode::End => Some(Key::End),
        KeyCode::F(number) => Some(Key::F(number)),
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
    let mut inbound_open = true;
    while app.running {
        terminal.draw(|frame| app.draw(frame))?;
        let pause = tokio::time::sleep(app.pause());
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
            () = pause => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{Signed, sign::generate_key};
    use jiff::tz::TimeZone;
    use tokio::sync::mpsc::{self, UnboundedReceiver};

    use super::*;

    /// A live console on a test channel, with Containment's proposal waiting for a signature.
    fn console() -> (App, UnboundedReceiver<Envelope>) {
        let (outbound, sent) = mpsc::unbounded_channel();
        let key = generate_key().expect("test randomness");
        let session = Session::new(key, outbound);
        let mut app = App::live(
            State::new(TimeZone::UTC),
            View::live(vec!["ransomware".to_owned()]),
            session,
            "debian".to_owned(),
        );
        let proposal = BusMessage {
            id: "m1".to_owned(),
            at: "2026-11-08T04:40:00Z".to_owned(),
            from: Principal::Agent {
                role: Role::Containment,
            },
            to: Audience::All,
            body: BusBody::Proposal {
                proposal_id: "INC-7-proposal-1".to_owned(),
                action: "isolate host acme-fs".to_owned(),
                rationale: "ransomware on the share".to_owned(),
            },
        };
        app.on_frame(Envelope {
            v: WIRE_VERSION,
            frame: Frame::Event(Signed {
                domain: domain::BUS.to_owned(),
                body: proposal,
                signer: "sha256:00".to_owned(),
                sig: "00".to_owned(),
            }),
        });
        (app, sent)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn type_text(app: &mut App, text: &str) {
        for typed in text.chars() {
            press(app, KeyCode::Char(typed));
        }
    }

    /// Every frame the console queued so far.
    fn drain(sent: &mut UnboundedReceiver<Envelope>) -> Vec<Frame> {
        std::iter::from_fn(|| sent.try_recv().ok())
            .map(|envelope| envelope.frame)
            .collect()
    }

    #[test]
    fn typing_in_the_message_line_never_fires_a_command() {
        let (mut app, mut sent) = console();
        press(&mut app, KeyCode::F(2));
        assert_eq!(
            app.view.focus,
            Focus::Input,
            "the Lead tab opens on the message line"
        );

        type_text(&mut app, "approve? x d q");
        assert!(
            drain(&mut sent).is_empty(),
            "no approval, detonation or quit"
        );
        assert!(app.running, "q was text");
        assert_eq!(app.view.draft, "approve? x d q");

        press(&mut app, KeyCode::Enter);
        let frames = drain(&mut sent);
        let [Frame::Publish(signed)] = frames.as_slice() else {
            panic!("one publish, got {frames:?}");
        };
        assert_eq!(signed.body.to, Audience::Role { role: Role::Lead });
        assert_eq!(
            signed.body.body,
            BusBody::Chat {
                text: "approve? x d q".to_owned()
            }
        );
        assert!(app.view.draft.is_empty(), "the line clears once sent");
    }

    #[test]
    fn esc_leaves_the_line_and_the_keys_command_again() {
        let (mut app, mut sent) = console();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "draft");
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.view.focus, Focus::Keys);

        press(&mut app, KeyCode::Char('a'));
        let frames = drain(&mut sent);
        assert!(
            matches!(
                frames.as_slice(),
                [Frame::Request {
                    request: CoreRequest::Approve(_),
                    ..
                }]
            ),
            "a approves the waiting proposal: {frames:?}"
        );
        assert_eq!(app.view.draft, "draft", "the draft waits for the commander");

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.view.focus, Focus::Input, "Enter returns to the line");
    }

    #[test]
    fn an_at_name_goes_to_that_specialist_and_a_typo_goes_nowhere() {
        let (mut app, mut sent) = console();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "@hunter what did the note ask for?");
        press(&mut app, KeyCode::Enter);
        let frames = drain(&mut sent);
        let [Frame::Publish(signed)] = frames.as_slice() else {
            panic!("one publish, got {frames:?}");
        };
        assert_eq!(signed.body.to, Audience::Role { role: Role::Hunter });
        assert_eq!(
            signed.body.body,
            BusBody::Chat {
                text: "what did the note ask for?".to_owned()
            }
        );

        type_text(&mut app, "@zed hello");
        press(&mut app, KeyCode::Enter);
        assert!(drain(&mut sent).is_empty(), "nobody is called zed");
        assert_eq!(app.view.draft, "@zed hello", "the draft is kept to fix");
    }

    #[test]
    fn function_keys_and_tab_switch_tabs_from_either_focus() {
        let (mut app, _sent) = console();
        assert_eq!((app.view.tab, app.view.focus), (Tab::Overview, Focus::Keys));
        press(&mut app, KeyCode::F(3));
        press(&mut app, KeyCode::Tab);
        assert_eq!(
            app.view.tab,
            Tab::Record,
            "F3 is Scope, Tab steps to Record"
        );
        press(&mut app, KeyCode::F(10));
        assert_eq!(
            (app.view.tab, app.view.focus),
            (Tab::Controlroom, Focus::Keys)
        );
        press(&mut app, KeyCode::Char('c'));
        assert_eq!(app.view.focus, Focus::Input, "c opens the Controlroom chat");
        type_text(&mut app, "t");
        press(&mut app, KeyCode::F(1));
        assert_eq!((app.view.tab, app.view.focus), (Tab::Overview, Focus::Keys));
        assert_eq!(app.view.draft, "t", "t was typed, not a tamper");
    }
}
