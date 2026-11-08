//! Rendering: draws a [`State`] and a [`View`] into one ratatui frame.
//!
//! Two screens share one top bar and one hint bar. **Cleanroom**, the default, is the commander's
//! conversation with the Lead agent beside the team and the situation at a glance.
//! **Controlroom** is the dense operator view, with every OS denial pinned so it never scrolls
//! away. Text sits next to every color, so nothing depends on color alone.

mod cleanroom;
mod controlroom;
mod overlays;

use std::cell::Cell;

use cleanroom_proto::{IncidentStatus, LlmMode, MemberRole, Role, Severity, Tri};
use jiff::Timestamp;
use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use unicode_width::UnicodeWidthChar as _;

use crate::access::Enrollment;
use crate::clocks::{self, Clock, ClockState, Urgency};
use crate::state::{State, Tone, Who, compromised};
use crate::team;
use crate::theme::{
    ACCENT, ACCENT_BG, AMBER, AMBER_BG, BRIGHT, Colors, DIM, INK, LINE, MUTED, RAISED, RAISED_HI,
    RED, RED_BG, TEXT, glyph, strip, tint,
};

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

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    /// The conversation with the Lead, the team and the situation.
    Cleanroom,
    /// The dense operator view.
    Controlroom,
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
    /// The screen showing.
    pub(crate) screen: Screen,
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
    /// Whether color may be used.
    pub(crate) colors: Colors,
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

    /// Shared constructor: the Cleanroom screen with the message line focused.
    const fn new(link: Link, scenarios: Vec<String>) -> Self {
        Self {
            link,
            scenarios,
            selected: 0,
            overlay: Overlay::None,
            admission_seen: 0,
            screen: Screen::Cleanroom,
            focus: Focus::Input,
            draft: String::new(),
            scroll: 0,
            scroll_limit: Cell::new(0),
            pane: Pane::Approvals,
            trace: None,
            access: AccessForm::new(),
            colors: Colors::Full,
        }
    }

    /// The same view drawing with `colors`.
    #[must_use]
    pub(crate) const fn with_colors(mut self, colors: Colors) -> Self {
        self.colors = colors;
        self
    }

    /// False only when a live link has dropped.
    pub(crate) const fn connected(&self) -> bool {
        !matches!(self.link, Link::Live { down: Some(_) })
    }

    /// Whether an admission result is waiting to be dismissed.
    pub(crate) const fn admission_visible(&self, state: &State) -> bool {
        state.admission.is_some() && state.admission_seq > self.admission_seen
    }

    /// Show `screen`; the Cleanroom screen opens with the message line focused.
    pub(crate) const fn show(&mut self, screen: Screen) {
        self.screen = screen;
        self.focus = match screen {
            Screen::Cleanroom => Focus::Input,
            Screen::Controlroom => Focus::Keys,
        };
    }
}

/// Draw the whole console at `now`.
pub fn render(frame: &mut Frame<'_>, state: &State, view: &View, now: Timestamp) {
    let area = frame.area();
    frame.render_widget(Block::new().style(Style::new().bg(INK).fg(TEXT)), area);
    let roomy = area.height >= 40;
    let typing_here = view.screen == Screen::Controlroom && view.focus == Focus::Input;
    let (items, fixed) = hint_items(view);
    let wide = hints_width(items) + hints_width(fixed) + 1 > usize::from(area.width);
    let hint_rows = if roomy && wide && !typing_here { 2 } else { 1 };
    let [top, _, body, hints] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(u16::from(roomy)),
        Constraint::Fill(1),
        Constraint::Length(hint_rows),
    ])
    .areas(area);
    render_top(frame, top, state, view, now);
    match view.screen {
        Screen::Cleanroom => cleanroom::render(frame, body, state, view, now),
        Screen::Controlroom => controlroom::render(frame, body, state, view, now),
    }
    if typing_here {
        controlroom::render_message_line(frame, hints, view);
    } else {
        render_hints(frame, hints, (items, fixed));
    }
    overlays::render(frame, area, state, view);
    if view.colors == Colors::Off {
        strip(frame.buffer_mut());
    }
}

// ---------- Top bar ----------

/// Brand, incident and screen tabs on the first row; vital chips on the second.
fn render_top(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    frame.render_widget(Block::new().style(Style::new().bg(RAISED)), area);
    let [first, second] = Layout::vertical([Constraint::Length(1); 2]).areas(area);
    let tabs = tabs(view.screen);
    let tabs_width = u16::try_from(tabs.width()).unwrap_or(u16::MAX);
    let [brand, tabs_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(tabs_width)]).areas(first);
    frame.render_widget(
        Paragraph::new(brand_line(state, usize::from(brand.width))),
        brand,
    );
    frame.render_widget(Paragraph::new(tabs), tabs_area);
    let link = link_chips(view, state);
    let link_width = u16::try_from(link.width()).unwrap_or(u16::MAX);
    let [vitals, link_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(link_width)]).areas(second);
    let vitals_line = vitals_line(state, now, usize::from(vitals.width));
    frame.render_widget(Paragraph::new(vitals_line), vitals);
    frame.render_widget(Paragraph::new(link), link_area);
}

/// `◇ CLEANROOM   INC-7  Ransomware on acme-fs  ·  ANALYZING  ·  HIGH`, in `width` columns: a
/// long title is cut so the status and severity always show.
fn brand_line(state: &State, width: usize) -> Line<'static> {
    let mut spans = vec![
        Span::raw("  ◇ ").fg(ACCENT).bold(),
        Span::raw("CLEANROOM").fg(BRIGHT).bold(),
        Span::raw("    "),
    ];
    let pill = Style::new().bg(RAISED_HI);
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

/// The two screen tabs, the active one lit.
fn tabs(screen: Screen) -> Line<'static> {
    let tab = |key: &'static str, name: &'static str, active: bool| {
        if active {
            [
                Span::styled(format!(" {key} "), Style::new().fg(ACCENT).bg(ACCENT_BG)),
                Span::styled(
                    format!("{name} "),
                    Style::new().fg(BRIGHT).bg(ACCENT_BG).bold(),
                ),
            ]
        } else {
            [
                Span::styled(format!(" {key} "), Style::new().fg(DIM)),
                Span::styled(format!("{name} "), Style::new().fg(MUTED)),
            ]
        }
    };
    let mut spans = Vec::with_capacity(6);
    spans.extend(tab("F1", "Cleanroom", screen == Screen::Cleanroom));
    spans.push(Span::raw(" "));
    spans.extend(tab("F2", "Controlroom", screen == Screen::Controlroom));
    spans.push(Span::raw("  "));
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

/// Next deadline, assets compromised, kernel blocks, guardrails and approvals waiting, in
/// `width` columns: short forms when the long ones don't fit, then the last chips dropped.
fn vitals_line(state: &State, now: Timestamp, width: usize) -> Line<'static> {
    let mut chips = vec![next_deadline(state, now), assets_chip(state)];
    let blocks = state.blocks();
    let noun = if blocks == 1 { "block" } else { "blocks" };
    chips.push(Chip {
        label: ("KERNEL", "KERNEL"),
        value: (format!("{blocks} {noun}"), format!("{blocks} {noun}")),
        color: if blocks > 0 { RED } else { ACCENT },
    });
    let (guardrails, color) = if state.guardrails {
        ("ON", ACCENT)
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
            color: AMBER,
        });
    }
    let line = |chips: &[Chip], short: bool| {
        let mut spans = vec![Span::raw("    ")];
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

/// LIVE / DISCONNECTED / REPLAY, and the agents' model mode when it is not live.
fn link_chips(view: &View, state: &State) -> Line<'static> {
    let mut spans = Vec::with_capacity(4);
    if let Some(counters) = state.counters {
        match counters.llm {
            LlmMode::Live => {}
            LlmMode::Record => spans.push(Span::raw("LLM recording   ").fg(MUTED)),
            LlmMode::Replay => spans.push(Span::styled(
                " LLM REPLAY ",
                Style::new().fg(BRIGHT).bg(AMBER_BG).bold(),
            )),
        }
        spans.push(Span::raw("   "));
    }
    spans.push(link_badge(&view.link));
    spans.push(Span::raw("  "));
    Line::from(spans)
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

/// Severity word on the incident pill.
fn severity_span(severity: Severity, pill: Style) -> Span<'static> {
    let (word, color) = match severity {
        Severity::Critical => ("CRITICAL", RED),
        Severity::High => ("HIGH", RED),
        Severity::Moderate => ("MODERATE", AMBER),
        Severity::Low => ("LOW", MUTED),
    };
    Span::styled(word, pill.fg(color).bold())
}

// ---------- Hint bar ----------

/// Key and label pairs for the hint bar.
type Hints = &'static [(&'static str, &'static str)];

/// Key hints for the current screen and focus: the list, then the keys pinned to the right.
const fn hint_items(view: &View) -> (Hints, Hints) {
    match (view.overlay, view.screen, view.focus) {
        (Overlay::Members, ..) => (&[("Esc", "close")], &[]),
        (Overlay::Help | Overlay::Detonate { .. } | Overlay::ConfirmReset, ..) => {
            (&[("Esc", "close")], &[("q", "quit")])
        }
        (Overlay::None, Screen::Cleanroom, Focus::Input) => (
            &[
                ("Enter", "send to the Lead"),
                ("@hunter", "ask a specialist"),
                ("Esc", "command keys"),
                ("PgUp/PgDn", "scroll"),
            ],
            &[("Tab", "Controlroom"), ("Ctrl+C", "quit")],
        ),
        (Overlay::None, Screen::Cleanroom, Focus::Keys) => (
            CLEANROOM_KEYS,
            &[("Tab", "Controlroom"), ("?", "help"), ("q", "quit")],
        ),
        (Overlay::None, Screen::Controlroom, Focus::Input | Focus::Keys) => (
            CONTROLROOM_KEYS,
            &[("Tab", "Cleanroom"), ("?", "help"), ("q", "quit")],
        ),
    }
}

/// Columns `hints` take on one line.
fn hints_width(hints: Hints) -> usize {
    hints
        .iter()
        .map(|(key, label)| hint(key, label).iter().map(Span::width).sum::<usize>())
        .sum()
}

/// The hints, wrapped over the rows of `area`; the pinned keys stay at the right of the first
/// row. Hints that still don't fit are left to the `?` help.
fn render_hints(frame: &mut Frame<'_>, area: Rect, (items, fixed): (Hints, Hints)) {
    let width = usize::from(area.width);
    let pinned: Vec<Span<'static>> = fixed
        .iter()
        .flat_map(|(key, label)| hint(key, label))
        .collect();
    let pinned_width: usize = pinned.iter().map(Span::width).sum();
    let mut rows: Vec<Vec<Span<'static>>> = vec![vec![Span::raw(" ")]];
    let mut used = 1;
    let rows_available = usize::from(area.height).max(1);
    for (key, label) in items {
        let pair = hint(key, label);
        let pair_width: usize = pair.iter().map(Span::width).sum();
        let room = if rows.len() == 1 {
            width.saturating_sub(pinned_width)
        } else {
            width
        };
        if used + pair_width > room {
            if rows.len() == rows_available {
                break;
            }
            rows.push(vec![Span::raw(" ")]);
            used = 1;
        }
        used += pair_width;
        if let Some(row) = rows.last_mut() {
            row.extend(pair);
        }
    }
    for (index, row) in rows.into_iter().enumerate() {
        let y = area
            .y
            .saturating_add(u16::try_from(index).unwrap_or(u16::MAX));
        frame.render_widget(
            Paragraph::new(Line::from(row)),
            Rect {
                y,
                height: 1,
                ..area
            },
        );
    }
    let pinned_width = u16::try_from(pinned_width).unwrap_or(u16::MAX);
    let [_, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(pinned_width)])
        .areas(Rect { height: 1, ..area });
    frame.render_widget(Paragraph::new(Line::from(pinned)), right);
}

/// Command keys on the Cleanroom screen, most important first.
const CLEANROOM_KEYS: Hints = &[
    ("Enter", "talk"),
    ("a/x", "approve/deny"),
    ("↑↓", "select"),
    ("d", "detonate"),
    ("t", "tamper"),
    ("A", "admit"),
    ("g", "guardrails"),
    ("i", "investigate"),
    ("v", "verify log"),
    ("r", "reset"),
    ("m", "members"),
];

/// Command keys on the Controlroom screen, most important first.
const CONTROLROOM_KEYS: Hints = &[
    ("a/x", "approve/deny"),
    ("↑↓", "select"),
    ("←→", "pane"),
    ("Enter", "expand"),
    ("c", "chat"),
    ("d", "detonate"),
    ("t", "tamper"),
    ("A", "admit"),
    ("g", "guardrails"),
    ("i", "investigate"),
    ("v", "verify log"),
    ("r", "reset"),
    ("m", "members"),
];

/// One keycap and its label.
fn hint(key: &str, label: &str) -> [Span<'static>; 2] {
    [
        Span::styled(
            format!(" {key} "),
            Style::new().fg(BRIGHT).bg(RAISED_HI).bold(),
        ),
        Span::raw(format!(" {label}  ")).fg(MUTED),
    ]
}

// ---------- Shared pieces ----------

/// A section heading: quiet, upper-case, with breathing room after it.
pub(super) fn heading(text: &str) -> Line<'static> {
    Line::from(Span::raw(text.to_owned()).fg(MUTED).bold())
}

/// A rounded panel with a quiet border and `title`.
pub(super) fn panel(title: Line<'static>, focused: bool) -> Block<'static> {
    let border = if focused { ACCENT } else { LINE };
    Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::new().fg(border))
        .title(title)
}

/// A panel title: ` NAME ` in quiet bold, lit when the panel has focus.
pub(super) fn title(text: &str, focused: bool) -> Line<'static> {
    let color = if focused { ACCENT } else { MUTED };
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
        Tone::Good => ACCENT,
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
        Tri::No => ("no", Style::new().fg(ACCENT).bg(ACCENT_BG)),
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
