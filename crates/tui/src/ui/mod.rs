//! Rendering: draws a [`State`] and a [`View`] into one ratatui frame.
//!
//! The Cleanroom app is a row of tabs under a pixel-art banner whose sky shows the incident's
//! state: Overview, Lead, Scope, Record, Defense, Team and Memory, plus the Controlroom, the dense
//! operator screen with every OS denial pinned. Text sits next to every color, so nothing depends
//! on color alone.

mod banner;
mod controlroom;
mod lead;
mod memory;
mod overlays;
mod tabs;

use std::cell::Cell;

use cleanroom_proto::{IncidentStatus, LlmMode, MemberRole, Role, Severity, Tri};
use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
use unicode_width::UnicodeWidthChar as _;

use crate::access::Enrollment;
use crate::clocks::{self, Clock, ClockState, Urgency};
use crate::state::{State, Tone, Who, compromised};
use crate::team;
use crate::theme::{
    ACCENT, ACCENT_BG, AMBER, AMBER_BG, BRIGHT, Colors, DIM, FOCUS, INK, LINE, MUTED, Name, OK,
    RAISED, RAISED_HI, RED, RED_BG, RULE, TEXT, Theme, blend, glyph, strip, tint,
};

/// The key that cycles the theme, for the key bar.
const THEME_KEY: (&str, &str) = ("T", "Theme");
/// How long a daemon answer stays in the corner toast.
const TOAST_FOR: SignedDuration = SignedDuration::from_secs(6);

/// How the console is fed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Link {
    /// Talking to cleanroomd; `down` says why the link dropped, if it did.
    Live {
        /// Reason the connection ended.
        down: Option<String>,
    },
    /// Playing a recording.
    Replay {
        /// Playback speed multiplier.
        speed: f64,
        /// All recorded frames have played.
        finished: bool,
    },
}

/// The tab showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// F1: what happened, what's at risk, what to do next.
    Overview,
    /// F2: the conversation with the Lead.
    Lead,
    /// F3: every asset's scope record.
    Scope,
    /// F4: the incident record, timeline and legal clocks.
    Record,
    /// F5: what each defense layer stopped.
    Defense,
    /// F6: the agents.
    Team,
    /// F7: each agent's working context, span by span.
    Memory,
    /// F10: the dense operator screen.
    Controlroom,
}

impl Tab {
    /// Every tab, in tab-bar order.
    pub(crate) const ALL: [Self; 8] = [
        Self::Overview,
        Self::Lead,
        Self::Scope,
        Self::Record,
        Self::Defense,
        Self::Team,
        Self::Memory,
        Self::Controlroom,
    ];

    /// The tab a function key opens: F1 to F6, and F10.
    pub(crate) const fn for_key(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::Overview),
            2 => Some(Self::Lead),
            3 => Some(Self::Scope),
            4 => Some(Self::Record),
            5 => Some(Self::Defense),
            6 => Some(Self::Team),
            7 => Some(Self::Memory),
            10 => Some(Self::Controlroom),
            _ => None,
        }
    }

    /// The next tab (`forward`) or the previous one, wrapping around.
    pub(crate) fn step(self, forward: bool) -> Self {
        let index = Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0);
        let count = Self::ALL.len();
        let next = if forward {
            (index + 1) % count
        } else {
            (index + count - 1) % count
        };
        Self::ALL.get(next).copied().unwrap_or(self)
    }

    /// Name and function key on the tab bar.
    const fn label(self) -> (&'static str, &'static str) {
        match self {
            Self::Overview => ("Overview", "F1"),
            Self::Lead => ("Lead", "F2"),
            Self::Scope => ("Scope", "F3"),
            Self::Record => ("Record", "F4"),
            Self::Defense => ("Defense", "F5"),
            Self::Team => ("Team", "F6"),
            Self::Memory => ("Memory", "F7"),
            Self::Controlroom => ("Controlroom", "F10"),
        }
    }

    /// Nickname and one-line description for the subtitle.
    const fn about(self) -> (&'static str, &'static str) {
        match self {
            Self::Overview => (
                "the room",
                "What happened, what's at risk, and what to do next. Each line names the key that goes there.",
            ),
            Self::Lead => (
                "the line",
                "Talk to the Lead; it asks the specialists for you. @hunter asks one directly. Esc for keys.",
            ),
            Self::Scope => (
                "the vault",
                "Every asset: what was locked, taken or touched, how sure the team is, and the evidence.",
            ),
            Self::Record => (
                "the ledger",
                "The incident record, its timeline, and every legal notification clock with its deadline.",
            ),
            Self::Defense => (
                "the walls",
                "What each layer stopped: the safety model, the agents' own refusals, and the kernel grant.",
            ),
            Self::Team => (
                "the crew",
                "The Lead and the four specialists: model, live status, recent steps and findings.",
            ),
            Self::Memory => (
                "the stacks",
                "Each agent's working context: what sits verbatim, what is paged out to a digest, and every move.",
            ),
            Self::Controlroom => (
                "the deck",
                "Everything at once: pinned OS blocks, scope, trace, the Lead, the team and approvals.",
            ),
        }
    }
}

/// The views of the Overview's activity chart, its sub-tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChartView {
    /// Tool calls, OS denials and safety flags.
    All,
    /// Tool calls and OS denials.
    Exec,
    /// Safety flags.
    Safety,
}

impl ChartView {
    /// The next view (`forward`) or the previous one, wrapping around.
    pub(crate) const fn step(self, forward: bool) -> Self {
        match (self, forward) {
            (Self::All, true) | (Self::Safety, false) => Self::Exec,
            (Self::Exec, true) | (Self::All, false) => Self::Safety,
            (Self::Safety, true) | (Self::Exec, false) => Self::All,
        }
    }
}

/// Where typed keys go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Focus {
    /// Into the message line: no key is a command.
    Input,
    /// Command keys.
    Keys,
}

/// The Controlroom pane that ↑↓ move in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pane {
    /// The approvals queue.
    Approvals,
    /// The agent trace.
    Trace,
}

impl Pane {
    /// The other pane.
    pub(crate) const fn other(self) -> Self {
        match self {
            Self::Approvals => Self::Trace,
            Self::Trace => Self::Approvals,
        }
    }
}

/// A modal panel on top of the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overlay {
    /// No modal.
    None,
    /// Key reference.
    Help,
    /// Scenario picker for `d`; `cursor` indexes the scenario list.
    Detonate {
        /// Highlighted scenario.
        cursor: usize,
    },
    /// Confirmation for `r`.
    ConfirmReset,
    /// Access control: members, enrollment and revocation.
    Members,
}

/// The part of the access-control overlay that has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    /// The member list.
    List,
    /// The public key to enroll.
    Key,
    /// The member's name.
    Name,
    /// The member's role.
    Role,
}

/// The access-control overlay's state: selection, the enroll form and a revoke prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessForm {
    /// Focused part.
    pub(crate) field: Field,
    /// Selected row: 0 is this console, then the roster in order.
    pub(crate) selected: usize,
    /// Public key being typed (64 hex digits).
    pub(crate) key: String,
    /// Name being typed.
    pub(crate) name: String,
    /// Role to enroll as.
    pub(crate) role: MemberRole,
    /// Reason being typed for revoking the selected member, while the prompt is open.
    pub(crate) reason: Option<String>,
}

impl AccessForm {
    /// An empty form with the list focused.
    const fn new() -> Self {
        Self {
            field: Field::List,
            selected: 0,
            key: String::new(),
            name: String::new(),
            role: MemberRole::Commander,
            reason: None,
        }
    }
}

/// Console-only state: what is selected, open or being typed. Never sent anywhere.
#[derive(Debug)]
pub struct View {
    /// Live or replay, and the link's health.
    pub(crate) link: Link,
    /// Scenarios offered by the detonate picker.
    pub(crate) scenarios: Vec<String>,
    /// Selected approvals-queue row.
    pub(crate) selected: usize,
    /// Open modal.
    pub(crate) overlay: Overlay,
    /// Last admission result the commander dismissed.
    pub(crate) admission_seen: u64,
    /// The tab showing.
    pub(crate) tab: Tab,
    /// Where typed keys go.
    pub(crate) focus: Focus,
    /// The message being typed; kept when focus leaves the input.
    pub(crate) draft: String,
    /// Conversation lines scrolled back from the newest.
    pub(crate) scroll: usize,
    /// The furthest the conversation can scroll back, as last drawn; keys clamp to it.
    pub(crate) scroll_limit: Cell<usize>,
    /// The Controlroom pane ↑↓ move in.
    pub(crate) pane: Pane,
    /// Selected (and expanded) agent-trace line; `None` follows the newest.
    pub(crate) trace: Option<usize>,
    /// The access-control overlay.
    pub(crate) access: AccessForm,
    /// The notice the corner toast shows and when it first appeared.
    pub(crate) toast: Cell<(u64, Option<Timestamp>)>,
    /// Whether color may be used.
    pub(crate) colors: Colors,
    /// The focused panel on the current tab, counted left to right, top to bottom.
    pub(crate) panel: usize,
    /// The Overview chart's sub-tab.
    pub(crate) chart: ChartView,
    /// Whether things move: the banner, pulses and fades.
    pub(crate) motion: bool,
    /// The color theme.
    pub(crate) theme: Name,
}

impl View {
    /// View for a live connection offering `scenarios` to detonate.
    #[must_use]
    pub const fn live(scenarios: Vec<String>) -> Self {
        Self::new(Link::Live { down: None }, scenarios)
    }

    /// View for replaying a recording at `speed`.
    #[must_use]
    pub const fn replay(speed: f64) -> Self {
        Self::new(
            Link::Replay {
                speed,
                finished: false,
            },
            Vec::new(),
        )
    }

    /// Shared constructor: the Overview tab with command keys.
    const fn new(link: Link, scenarios: Vec<String>) -> Self {
        Self {
            link,
            scenarios,
            selected: 0,
            overlay: Overlay::None,
            admission_seen: 0,
            tab: Tab::Overview,
            focus: Focus::Keys,
            draft: String::new(),
            scroll: 0,
            scroll_limit: Cell::new(0),
            pane: Pane::Approvals,
            trace: None,
            access: AccessForm::new(),
            toast: Cell::new((0, None)),
            colors: Colors::Full,
            panel: 0,
            chart: ChartView::All,
            motion: false,
            theme: Name::Cleanroom,
        }
    }

    /// The same view drawing with `colors`.
    #[must_use]
    pub(crate) const fn with_colors(mut self, colors: Colors) -> Self {
        self.colors = colors;
        self
    }

    /// The same view, animated when `motion`.
    #[must_use]
    pub(crate) const fn with_motion(mut self, motion: bool) -> Self {
        self.motion = motion;
        self
    }

    /// The same view in `theme`.
    #[must_use]
    pub(crate) const fn with_theme(mut self, theme: Name) -> Self {
        self.theme = theme;
        self
    }

    /// The active palette.
    pub(crate) const fn palette(&self) -> &'static Theme {
        self.theme.theme()
    }

    /// Move the focus to the next panel (`forward`) or the previous one on the current tab.
    pub(crate) fn move_focus(&mut self, state: &State, now: Timestamp, forward: bool) {
        let count = tabs::panel_count(state, self, now).max(1);
        let current = self.panel % count;
        self.panel = if forward {
            (current + 1) % count
        } else {
            (current + count - 1) % count
        };
    }

    /// False only when a live link has dropped.
    pub(crate) const fn connected(&self) -> bool {
        !matches!(self.link, Link::Live { down: Some(_) })
    }

    /// Whether an admission result is waiting to be dismissed.
    pub(crate) const fn admission_visible(&self, state: &State) -> bool {
        state.admission.is_some() && state.admission_seq > self.admission_seen
    }

    /// Show `tab`, its first panel focused; the Lead tab opens with the message line focused,
    /// every other with keys.
    pub(crate) const fn show(&mut self, tab: Tab) {
        self.tab = tab;
        self.panel = 0;
        self.focus = match tab {
            Tab::Lead => Focus::Input,
            Tab::Overview
            | Tab::Scope
            | Tab::Record
            | Tab::Defense
            | Tab::Team
            | Tab::Memory
            | Tab::Controlroom => Focus::Keys,
        };
    }
}

/// Draw the whole console at `now`.
pub fn render(frame: &mut Frame<'_>, state: &State, view: &View, now: Timestamp) {
    let area = frame.area();
    frame.render_widget(Block::new().style(Style::new().bg(INK).fg(TEXT)), area);
    if view.tab == Tab::Controlroom {
        let [bar, pill, chips, body, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        render_tab_bar(frame, bar, view);
        frame.render_widget(
            Paragraph::new(incident_pill(state, usize::from(pill.width))).bg(RAISED),
            pill,
        );
        frame.render_widget(
            Paragraph::new(vitals_line(state, view, now, usize::from(chips.width))).bg(RAISED),
            chips,
        );
        controlroom::render(frame, body, state, view, now);
        render_keys(frame, keys, state, view, now);
    } else {
        let banner_rows = if area.height >= 36 { banner::HEIGHT } else { 0 };
        let [sky, bar, subtitle, rule, body, keys] = Layout::vertical([
            Constraint::Length(banner_rows),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        if banner_rows > 0 {
            banner::render(
                frame,
                sky,
                banner::Sky::of(state),
                view.palette(),
                view.motion.then_some(now),
            );
        }
        render_tab_bar(frame, bar, view);
        render_subtitle(frame, subtitle, view.tab);
        frame.render_widget(
            Paragraph::new("─".repeat(usize::from(rule.width))).fg(RULE),
            rule,
        );
        match view.tab {
            Tab::Lead => lead::render(frame, body, state, view, now),
            Tab::Memory => memory::render(frame, body, state, view, now),
            Tab::Overview
            | Tab::Scope
            | Tab::Record
            | Tab::Defense
            | Tab::Team
            | Tab::Controlroom => tabs::render(frame, body, state, view, now),
        }
        render_keys(frame, keys, state, view, now);
    }
    render_toast(frame, area, state, view, now);
    overlays::render(frame, area, state, view);
    if view.colors == Colors::Off {
        strip(frame.buffer_mut());
    } else {
        view.palette().resolve(frame.buffer_mut());
    }
}

// ---------- Tab bar, subtitle, key bar, toast ----------

/// `◇ cleanroom   Overview F1   Lead F2 …`, the active tab a filled accent pill, the link on the
/// right.
fn render_tab_bar(frame: &mut Frame<'_>, area: Rect, view: &View) {
    frame.render_widget(Block::new().style(Style::new().bg(RAISED)), area);
    let mut spans = vec![
        Span::raw(" ◇ ").fg(ACCENT).bold(),
        Span::raw("cleanroom").fg(BRIGHT).bold(),
        Span::raw("   "),
    ];
    for tab in Tab::ALL {
        let (name, key) = tab.label();
        if tab == view.tab {
            let pill = Style::new().fg(INK).bg(ACCENT);
            spans.push(Span::styled(
                format!(" {name} "),
                pill.add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!("{key} "), pill));
        } else {
            spans.push(Span::raw(format!(" {name} ")).fg(TEXT));
            spans.push(Span::raw(format!("{key} ")).fg(DIM));
        }
        spans.push(Span::raw(" "));
    }
    let link = link_badge(&view.link);
    let link_width = u16::try_from(link.width() + 2).unwrap_or(u16::MAX);
    let [tabs_area, link_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(link_width)]).areas(area);
    frame.render_widget(Paragraph::new(Line::from(spans)), tabs_area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![link, Span::raw("  ")])),
        link_area,
    );
}

/// `✦ OVERVIEW the room  What happened, …`.
fn render_subtitle(frame: &mut Frame<'_>, area: Rect, tab: Tab) {
    let (name, _) = tab.label();
    let (nickname, about) = tab.about();
    let lead = format!(" ✦ {} {nickname}  ", name.to_uppercase());
    let line = Line::from(vec![
        Span::raw(" ✦ ").fg(ACCENT).bold(),
        Span::raw(name.to_uppercase()).fg(ACCENT).bold(),
        Span::raw(" "),
        Span::raw(nickname).fg(MUTED).italic(),
        Span::raw("  "),
        Span::raw(fit(
            about,
            usize::from(area.width).saturating_sub(width_of(&lead)),
        ))
        .fg(TEXT),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Key and action pairs for the key bar.
type Hints = &'static [(&'static str, &'static str)];

/// Amber that breathes while motion is on, for a signature that is waiting.
pub(super) fn pulse_amber(view: &View, now: Timestamp) -> Color {
    if !view.motion {
        return AMBER;
    }
    let theme = view.palette();
    let phase = now.as_millisecond().rem_euclid(1600);
    let depth = if phase < 800 { phase } else { 1600 - phase };
    blend(
        theme.amber,
        theme.amber_bg,
        u16::try_from(depth * 160 / 800).unwrap_or(0),
    )
}

/// The keys for the current tab, focus and modal: the list, then the keys pinned to the right.
const fn key_items(view: &View) -> (Hints, Hints) {
    match (view.overlay, view.tab, view.focus) {
        (Overlay::Members, ..) => (&[("Esc", "Close")], &[]),
        (Overlay::Help | Overlay::Detonate { .. } | Overlay::ConfirmReset, ..) => {
            (&[("Esc", "Close")], &[("q", "Quit")])
        }
        (Overlay::None, _, Focus::Input) => (
            &[
                ("Enter", "Send to the Lead"),
                ("@hunter", "Ask a specialist"),
                ("Esc", "Command keys"),
                ("PgUp/PgDn", "Scroll"),
                ("Tab", "Next tab"),
            ],
            &[("^C", "Quit")],
        ),
        (Overlay::None, Tab::Controlroom, Focus::Keys) => (
            &[
                ("a/x", "Approve/Deny"),
                ("↑↓", "Select"),
                ("←→", "Pane"),
                ("Enter", "Expand"),
                ("c", "Chat"),
                ("d", "Detonate"),
                ("t", "Tamper"),
                ("A", "Admit"),
                ("g", "Guardrails"),
                ("i", "Investigate"),
                ("v", "Verify"),
                ("r", "Reset"),
                ("m", "Members"),
                THEME_KEY,
            ],
            &[("?", "Help"), ("q", "Quit")],
        ),
        (
            Overlay::None,
            Tab::Overview
            | Tab::Lead
            | Tab::Scope
            | Tab::Record
            | Tab::Defense
            | Tab::Team
            | Tab::Memory,
            Focus::Keys,
        ) => (
            &[
                ("a/x", "Approve/Deny"),
                ("c", "Ask the Lead"),
                ("d", "Detonate"),
                ("t", "Tamper"),
                ("A", "Admit"),
                ("g", "Guardrails"),
                ("i", "Investigate"),
                ("v", "Verify log"),
                ("r", "Reset"),
                ("m", "Members"),
                THEME_KEY,
                ("Tab", "Next tab"),
            ],
            &[("?", "Help"), ("q", "Quit")],
        ),
    }
}

/// `key Action` pairs, the keys in the accent: the focused panel's keys first, then the tab's;
/// what doesn't fit is left to `?`.
fn render_keys(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let (items, pinned) = key_items(view);
    let panel_keys: Hints = match (view.overlay, view.tab, view.focus) {
        (
            Overlay::None,
            Tab::Overview | Tab::Scope | Tab::Record | Tab::Defense | Tab::Team,
            Focus::Keys,
        ) => tabs::focused_keys(state, view, now),
        _ => &[],
    };
    let focus: Hints = if panel_keys.is_empty() {
        &[]
    } else {
        &[("[ ]", "Focus")]
    };
    let pair = |(key, action): &(&str, &str)| {
        [
            Span::raw(format!(" {key} ")).fg(ACCENT).bold(),
            Span::raw(format!("{action} ")).fg(TEXT),
        ]
    };
    let right: Vec<Span<'static>> = pinned.iter().flat_map(pair).collect();
    let right_width: usize = right.iter().map(Span::width).sum();
    let room = usize::from(area.width).saturating_sub(right_width + 1);
    let items: Vec<&(&str, &str)> = panel_keys
        .iter()
        .chain(focus)
        .chain(
            items
                .iter()
                .filter(|(key, _)| !panel_keys.iter().any(|(taken, _)| taken == key)),
        )
        .collect();
    let mut left = Vec::new();
    let mut used = 0;
    for item in items {
        let spans = pair(item);
        let width: usize = spans.iter().map(Span::width).sum();
        if used + width > room {
            break;
        }
        used += width;
        left.extend(spans);
    }
    let [left_area, right_area] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(u16::try_from(right_width + 1).unwrap_or(u16::MAX)),
    ])
    .areas(area);
    frame.render_widget(Paragraph::new(Line::from(left)).bg(RAISED), left_area);
    frame.render_widget(Paragraph::new(Line::from(right)).bg(RAISED), right_area);
}

/// cleanroomd's latest answer, in a box at the bottom right for a few seconds.
fn render_toast(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let Some(notice) = &state.notice else {
        return;
    };
    let (seen, since) = view.toast.get();
    let since = if seen == state.notice_seq {
        since.unwrap_or(now)
    } else {
        view.toast.set((state.notice_seq, Some(now)));
        now
    };
    if now.duration_since(since) >= TOAST_FOR || area.height < 8 || area.width < 40 {
        return;
    }
    let width = 64.min(area.width.saturating_sub(4));
    let toast = Rect {
        x: area.right().saturating_sub(width + 2),
        y: area.bottom().saturating_sub(5),
        width,
        height: 3,
    };
    let color = match notice.tone {
        Tone::Bad => RED,
        Tone::Warn => AMBER,
        Tone::Good | Tone::Quiet | Tone::Plain => ACCENT,
    };
    frame.render_widget(Clear, toast);
    frame.render_widget(Block::new().style(Style::new().bg(RAISED_HI)), toast);
    let text = fit(&notice.text, usize::from(width).saturating_sub(4));
    let lines = vec![
        Line::from(Span::raw("▌").fg(color)),
        Line::from(vec![Span::raw("▌ ").fg(color), Span::raw(text).fg(BRIGHT)]),
        Line::from(Span::raw("▌").fg(color)),
    ];
    frame.render_widget(Paragraph::new(lines), toast);
}

// ---------- Controlroom header ----------

/// `INC-7  Ransomware on acme-fs  ·  ANALYZING  ·  HIGH`, in `width` columns: a long title is cut
/// so the status and severity always show.
fn incident_pill(state: &State, width: usize) -> Line<'static> {
    let pill = Style::new().bg(RAISED_HI);
    let mut spans = vec![Span::raw("  ")];
    match &state.incident {
        None => spans.push(Span::styled(" no incident declared ", pill.fg(DIM))),
        Some(incident) => {
            let mut tail = vec![
                Span::styled(" · ", pill.fg(DIM)),
                status_span(incident.status, pill),
                Span::styled(" · ", pill.fg(DIM)),
                severity_span(incident.severity, pill),
                Span::styled(" ", pill),
            ];
            let id = Span::styled(format!(" {} ", incident.id), pill.fg(MUTED));
            let used: usize = spans
                .iter()
                .chain(tail.iter())
                .chain(std::iter::once(&id))
                .map(Span::width)
                .sum();
            let title = fit(&incident.title, width.saturating_sub(used + 3));
            spans.push(id);
            spans.push(Span::styled(format!(" {title} "), pill.fg(BRIGHT).bold()));
            spans.append(&mut tail);
        }
    }
    Line::from(spans)
}

/// One vital chip: a quiet label and a bold value, each with a shorter form for narrow screens.
#[derive(Debug)]
struct Chip {
    /// Label, then its short form.
    label: (&'static str, &'static str),
    /// Value, then its short form.
    value: (String, String),
    /// Value color.
    color: Color,
}

/// Next deadline, assets compromised, kernel blocks, guardrails, approvals waiting and the
/// agents' model mode, in `width` columns: short forms when the long ones don't fit, then the
/// last chips dropped.
fn vitals_line(state: &State, view: &View, now: Timestamp, width: usize) -> Line<'static> {
    let mut chips = vec![next_deadline(state, now), assets_chip(state)];
    let blocks = state.blocks();
    let noun = if blocks == 1 { "block" } else { "blocks" };
    chips.push(Chip {
        label: ("KERNEL", "KERNEL"),
        value: (format!("{blocks} {noun}"), format!("{blocks} {noun}")),
        color: if blocks > 0 { RED } else { OK },
    });
    let (guardrails, color) = if state.guardrails {
        ("ON", OK)
    } else {
        ("OFF", AMBER)
    };
    chips.push(Chip {
        label: ("GUARDRAILS", "GUARD"),
        value: (guardrails.to_owned(), guardrails.to_owned()),
        color,
    });
    let waiting = state.waiting();
    if waiting > 0 {
        chips.push(Chip {
            label: ("APPROVALS", "SIGN"),
            value: (format!("{waiting} waiting"), format!("{waiting}")),
            color: pulse_amber(view, now),
        });
    }
    if let Some(counters) = state.counters
        && counters.llm != LlmMode::Live
    {
        let mode = if counters.llm == LlmMode::Replay {
            "REPLAY"
        } else {
            "recording"
        };
        chips.push(Chip {
            label: ("LLM", "LLM"),
            value: (mode.to_owned(), mode.to_owned()),
            color: AMBER,
        });
    }
    let line = |chips: &[Chip], short: bool| {
        let mut spans = vec![Span::raw("  ")];
        for chip in chips {
            let (label, value) = if short {
                (chip.label.1, chip.value.1.clone())
            } else {
                (chip.label.0, chip.value.0.clone())
            };
            spans.extend([
                Span::raw(label).fg(DIM),
                Span::raw(" "),
                Span::raw(value).fg(chip.color).bold(),
                Span::raw(if short { "   " } else { "     " }),
            ]);
        }
        Line::from(spans)
    };
    let long = line(&chips, false);
    if long.width() <= width {
        return long;
    }
    while chips.len() > 1 && line(&chips, true).width() > width {
        chips.pop();
    }
    line(&chips, true)
}

/// `TX AG notice 29d`, colored by urgency; `not started` before any clock runs.
fn next_deadline(state: &State, now: Timestamp) -> Chip {
    let label = ("NEXT DEADLINE", "DUE");
    running_clocks(state).first().map_or_else(
        || Chip {
            label,
            value: ("not started".to_owned(), "—".to_owned()),
            color: DIM,
        },
        |(clock, due)| {
            let remaining = due.duration_since(now);
            let left = clocks::short_remaining(remaining);
            Chip {
                label,
                value: (
                    format!("{} {left}", clock.regime.notice()),
                    format!("{} {left}", clock.regime.short_label()),
                ),
                color: urgency_color(clocks::urgency(remaining)),
            }
        },
    )
}

/// `2/4 compromised` in red, `1/4 unknown` in amber, or `4/4 clean` in the accent.
fn assets_chip(state: &State) -> Chip {
    let total = state.scope.len();
    let hit = state
        .scope
        .iter()
        .filter(|asset| compromised(asset.flags))
        .count();
    let unknown = state
        .scope
        .iter()
        .filter(|asset| !compromised(asset.flags) && has_unknown(asset))
        .count();
    let (long, short, color) = if total == 0 {
        ("none reported".to_owned(), "—".to_owned(), DIM)
    } else if hit > 0 {
        (
            format!("{hit}/{total} compromised"),
            format!("{hit}/{total} hit"),
            RED,
        )
    } else if unknown > 0 {
        (
            format!("{unknown}/{total} unknown"),
            format!("{unknown}/{total} ?"),
            AMBER,
        )
    } else {
        (
            format!("{total}/{total} clean"),
            format!("{total}/{total} ok"),
            ACCENT,
        )
    };
    Chip {
        label: ("ASSETS", "ASSETS"),
        value: (long, short),
        color,
    }
}

/// Whether any of an asset's flags is unknown.
fn has_unknown(asset: &cleanroom_proto::ScopeRecord) -> bool {
    let flags = asset.flags;
    [
        flags.locked,
        flags.exfiltrated,
        flags.accessed,
        flags.destroyed,
        flags.modified,
    ]
    .contains(&Tri::Unknown)
}

/// LIVE / DISCONNECTED / REPLAY badge.
fn link_badge(link: &Link) -> Span<'static> {
    match link {
        Link::Live { down: None } => Span::raw("● LIVE").fg(ACCENT).bold(),
        Link::Live { down: Some(_) } => Span::raw("✕ DISCONNECTED").fg(RED).bold(),
        Link::Replay {
            speed,
            finished: false,
        } => Span::raw(format!("▶ REPLAY {speed}×")).fg(AMBER).bold(),
        Link::Replay { finished: true, .. } => Span::raw("■ REPLAY ENDED").fg(AMBER).bold(),
    }
}

/// Incident lifecycle word on the incident pill.
fn status_span(status: IncidentStatus, pill: Style) -> Span<'static> {
    let color = match status {
        IncidentStatus::Detected => RED,
        IncidentStatus::Analyzing => AMBER,
        IncidentStatus::Contained | IncidentStatus::Eradicated | IncidentStatus::Recovered => {
            ACCENT
        }
        IncidentStatus::Closed => MUTED,
    };
    let word = crate::state::status_word(status).to_uppercase();
    Span::styled(word, pill.fg(color).bold())
}

/// Severity word and color.
pub(super) const fn severity_word(severity: Severity) -> (&'static str, Color) {
    match severity {
        Severity::Critical => ("CRITICAL", RED),
        Severity::High => ("HIGH", RED),
        Severity::Moderate => ("MODERATE", AMBER),
        Severity::Low => ("LOW", MUTED),
    }
}

/// Severity word on the incident pill.
fn severity_span(severity: Severity, pill: Style) -> Span<'static> {
    let (word, color) = severity_word(severity);
    Span::styled(word, pill.fg(color).bold())
}

// ---------- Shared pieces ----------

/// A section heading: quiet, upper-case, with breathing room after it.
pub(super) fn heading(text: &str) -> Line<'static> {
    Line::from(Span::raw(text.to_owned()).fg(MUTED).bold())
}

/// A rounded panel with a quiet border and `title`.
pub(super) fn panel(title: Line<'static>, focused: bool) -> Block<'static> {
    let border = if focused { FOCUS } else { LINE };
    Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::new().fg(border))
        .title(title)
}

/// A panel title: ` NAME ` in quiet bold, lit when the panel has focus.
pub(super) fn title(text: &str, focused: bool) -> Line<'static> {
    let color = if focused { FOCUS } else { MUTED };
    Line::from(Span::raw(format!(" {text} ")).fg(color).bold())
}

/// Upper-case sender label, at most 11 columns so log columns line up.
pub(super) fn who_label(who: &Who) -> String {
    match who {
        Who::Agent(role) => role_label(*role).to_owned(),
        Who::System => "SYSTEM".to_owned(),
        Who::Me => "YOU".to_owned(),
        Who::Human(short) => format!("HUMAN {}", short.chars().take(5).collect::<String>()),
    }
}

/// Upper-case role name.
pub(super) const fn role_label(role: Role) -> &'static str {
    match role {
        Role::Lead => "LEAD",
        Role::Hunter => "HUNTER",
        Role::Forensics => "FORENSICS",
        Role::Scribe => "SCRIBE",
        Role::Containment => "CONTAINMENT",
    }
}

/// A sender's tint: roles keep their subtle tint, people read as bright text.
pub(super) const fn who_color(who: &Who) -> Color {
    match who {
        Who::Agent(role) => tint(*role),
        Who::System => MUTED,
        Who::Me | Who::Human(_) => BRIGHT,
    }
}

/// `▲ Hunter` in the role's tint, for sentences.
pub(super) fn role_name(role: Role) -> Span<'static> {
    Span::raw(format!("{} {}", glyph(role), team::title(role))).fg(tint(role))
}

/// Color for a tone.
pub(super) const fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Quiet => DIM,
        Tone::Plain => MUTED,
        Tone::Good => OK,
        Tone::Warn => AMBER,
        Tone::Bad => RED,
    }
}

/// Text and colors for one scope flag: red on yes, amber on unknown, the accent on no. The word
/// is always there too, so the table still reads where color doesn't.
pub(super) const fn flag_look(value: Tri) -> (&'static str, Style) {
    match value {
        Tri::Yes => (
            "YES",
            Style::new()
                .fg(BRIGHT)
                .bg(RED_BG)
                .add_modifier(Modifier::BOLD),
        ),
        Tri::Unknown => (
            "?",
            Style::new()
                .fg(BRIGHT)
                .bg(AMBER_BG)
                .add_modifier(Modifier::BOLD),
        ),
        Tri::No => ("no", Style::new().fg(OK).bg(ACCENT_BG)),
    }
}

/// Color of a running clock.
pub(super) const fn urgency_color(urgency: Urgency) -> Color {
    match urgency {
        Urgency::Calm => TEXT,
        Urgency::Soon => AMBER,
        Urgency::Urgent | Urgency::Overdue => RED,
    }
}

/// Running clocks, soonest deadline first.
pub(super) fn running_clocks(state: &State) -> Vec<(Clock, Timestamp)> {
    let mut running: Vec<(Clock, Timestamp)> = clocks::clocks(&state.triggers(), &state.scope)
        .into_iter()
        .filter_map(|clock| match clock.state {
            ClockState::Running { due } => Some((clock, due)),
            ClockState::NotStarted | ClockState::NotApplicable(_) | ClockState::BadTrigger => None,
        })
        .collect();
    running.sort_by_key(|(_, due)| *due);
    running
}

/// Countdown, detail line and color for one clock.
pub(super) fn clock_text(clock: &Clock, now: Timestamp, tz: &TimeZone) -> (String, String, Color) {
    match &clock.state {
        ClockState::NotStarted => ("not started".to_owned(), "trigger not set".to_owned(), DIM),
        ClockState::NotApplicable(reason) => ("n/a".to_owned(), reason.clone(), DIM),
        ClockState::BadTrigger => (
            "bad trigger".to_owned(),
            "not a timestamp".to_owned(),
            AMBER,
        ),
        ClockState::Running { due } => {
            let remaining = due.duration_since(now);
            (
                clocks::countdown(remaining),
                format!("due {}", due_label(*due, tz, "%a %b %-d %H:%M %Z")),
                urgency_color(clocks::urgency(remaining)),
            )
        }
    }
}

/// `due` in the display zone with a strftime `format`.
pub(super) fn due_label(due: Timestamp, tz: &TimeZone, format: &str) -> String {
    let local = due.to_zoned(tz.clone());
    strtime::format(format, &local).unwrap_or_else(|_| local.to_string())
}

/// `lightning 30b` from `nvidia/nemotron-3.5-lightning-30b-a3b`: the model family and size.
pub(super) fn short_model(model: &str) -> String {
    let name = model.rsplit('/').next().unwrap_or(model);
    let parts: Vec<&str> = name.split('-').collect();
    let family = parts.iter().position(|part| {
        part.chars().all(|ch| ch.is_ascii_alphabetic())
            && !matches!(*part, "nemotron" | "nvidia" | "llama" | "instruct" | "chat")
    });
    match family.and_then(|index| parts.get(index).map(|word| (index, *word))) {
        Some((index, word)) => {
            let size = parts
                .iter()
                .skip(index + 1)
                .find(|part| part.ends_with('b') && part.chars().any(|ch| ch.is_ascii_digit()));
            size.map_or_else(|| word.to_owned(), |size| format!("{word} {size}"))
        }
        None => fit(name, 18),
    }
}

/// A braille spinner frame that turns four times a second.
pub(super) fn spinner(now: Timestamp) -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let tick = now.as_millisecond().div_euclid(100).rem_euclid(10);
    usize::try_from(tick)
        .ok()
        .and_then(|index| FRAMES.get(index))
        .copied()
        .unwrap_or("⠋")
}

/// `12,480`.
pub(super) fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Display width of `text` in terminal columns.
pub(super) fn width_of(text: &str) -> usize {
    text.chars().map(|ch| ch.width().unwrap_or(0)).sum()
}

/// `text` cut to `width` columns, with an ellipsis when cut.
pub(super) fn fit(text: &str, width: usize) -> String {
    if width_of(text) <= width {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let char_width = ch.width().unwrap_or(0);
        if used + char_width + 1 > width {
            break;
        }
        used += char_width;
        out.push(ch);
    }
    if width > 0 {
        out.push('…');
    }
    out
}

/// `text` padded with spaces (or cut) to exactly `width` columns.
pub(super) fn pad(text: &str, width: usize) -> String {
    let mut out = fit(text, width);
    let used = width_of(&out);
    out.extend(std::iter::repeat_n(' ', width.saturating_sub(used)));
    out
}

/// Word-wrap `text` to `width` columns, splitting words longer than a line. Newlines in `text`
/// start new lines.
pub(super) fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut used = 0;
        for word in paragraph.split(' ').filter(|word| !word.is_empty()) {
            let word_width = width_of(word);
            if used > 0 && used + 1 + word_width > width {
                lines.push(std::mem::take(&mut line));
                used = 0;
            }
            if used > 0 {
                line.push(' ');
                used += 1;
            }
            for ch in word.chars() {
                let char_width = ch.width().unwrap_or(0);
                if used + char_width > width {
                    lines.push(std::mem::take(&mut line));
                    used = 0;
                }
                line.push(ch);
                used += char_width;
            }
        }
        lines.push(line);
    }
    lines
}

/// A styled run of spaces `width` columns wide.
pub(super) fn spaces(width: usize, style: Style) -> Span<'static> {
    Span::styled(" ".repeat(width), style)
}

/// `span` drawn on `surface`: the surface fills in whatever the span leaves unset, so a badge
/// keeps its own background on a card.
pub(super) fn on(surface: Style, span: Span<'static>) -> Span<'static> {
    let style = surface.patch(span.style);
    span.style(style)
}

/// The end of `text` that fits in `width` columns, for a line being typed.
pub(super) fn tail_fit(text: &str, width: usize) -> String {
    let mut used = 0;
    let mut start = text.len();
    for (index, ch) in text.char_indices().rev() {
        let char_width = ch.width().unwrap_or(0);
        if used + char_width > width {
            break;
        }
        used += char_width;
        start = index;
    }
    text.get(start..).unwrap_or_default().to_owned()
}

/// The members listed under this console in the access-control overlay (list rows 1 and on):
/// everyone on the roster but this console's own key, in roster order.
pub(crate) fn listed_members(state: &State) -> Vec<&Enrollment> {
    let me = state.me.as_deref();
    state
        .roster
        .all()
        .iter()
        .filter(|member| Some(member.key_id.as_str()) != me)
        .collect()
}

/// The member the access-control list selects; row 0 is this console, when it is enrolled.
pub(crate) fn selected_member<'state>(
    state: &'state State,
    form: &AccessForm,
) -> Option<&'state Enrollment> {
    form.selected.checked_sub(1).map_or_else(
        || state.me.as_deref().and_then(|key| state.roster.get(key)),
        |index| listed_members(state).get(index).copied(),
    )
}

#[cfg(test)]
mod tests;
