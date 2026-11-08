//! Rendering: draws a [`State`] and a [`View`] into one ratatui frame.
//!
//! Built for a projector and for a stressed commander: one "what do I do now" line, persistent
//! key hints, big type for the tamper beat, and text next to every color so nothing depends on
//! color alone.

use cleanroom_proto::{DataClass, IncidentStatus, LlmMode, ScopeRecord, Severity, Tri};
use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Clear, Paragraph, Row, Table, Wrap};
use tui_big_text::{BigText, PixelSize};

use crate::clocks::{self, Clock, ClockState, Urgency};
use crate::next::{self, NextAction};
use crate::state::{Activity, Admission, Ask, LogStatus, QueueItem, State, Tone, Who};

/// Danger: a flag that is yes, a block, a failure.
const RED: Color = Color::Indexed(160);
/// Danger as text on black.
const BRIGHT_RED: Color = Color::Indexed(196);
/// Attention: unknown flags, waiting approvals, clocks inside three days.
const AMBER: Color = Color::Indexed(214);
/// Fine: a flag that is no, a verified log, guardrails on.
const GREEN: Color = Color::Indexed(34);
/// Neutral highlight that is neither good nor bad.
const BLUE: Color = Color::Indexed(75);
/// Secondary text.
const GRAY: Color = Color::Indexed(245);
/// Panel borders.
const BORDER: Color = Color::Indexed(240);
/// Background of the selected approval.
const SELECTED_BG: Color = Color::Indexed(237);
/// Width of the "REJECTED"/"ADMITTED" headline at half-height pixels.
const BIG_TEXT_WIDTH: u16 = 64;

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
    /// Chat message being typed, when the chat line is open.
    pub(crate) chat: Option<String>,
    /// Last admission result the commander dismissed.
    pub(crate) admission_seen: u64,
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

    /// Shared constructor.
    const fn new(link: Link, scenarios: Vec<String>) -> Self {
        Self {
            link,
            scenarios,
            selected: 0,
            overlay: Overlay::None,
            chat: None,
            admission_seen: 0,
        }
    }

    /// False only when a live link has dropped.
    pub(crate) const fn connected(&self) -> bool {
        !matches!(self.link, Link::Live { down: Some(_) })
    }

    /// Whether an admission result is waiting to be dismissed.
    pub(crate) const fn admission_visible(&self, state: &State) -> bool {
        state.admission.is_some() && state.admission_seq > self.admission_seen
    }
}

/// Draw the whole console at `now`.
pub fn render(frame: &mut Frame<'_>, state: &State, view: &View, now: Timestamp) {
    let area = frame.area();
    let compact = area.height < 34;
    let [header, clock_strip, now_panel, body, keys] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(if compact { 1 } else { 4 }),
        Constraint::Length(4),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);
    render_header(frame, header, state, view);
    let all = clocks::clocks(&state.triggers(), &state.scope);
    if compact {
        render_clock_line(frame, clock_strip, &all, now);
    } else {
        render_clock_boxes(frame, clock_strip, &all, now, &state.display_tz);
    }
    render_now(frame, now_panel, state, view, now);
    render_body(frame, body, state, view);
    render_keys(frame, keys, view);
    render_overlay(frame, area, state, view);
}

/// Text and colors for one scope flag: red on yes, amber on unknown, green on no. The word is
/// always there too, so the table still reads where color doesn't.
pub(crate) const fn flag_look(value: Tri) -> (&'static str, Style) {
    match value {
        Tri::Yes => (
            "YES",
            Style::new()
                .fg(Color::White)
                .bg(RED)
                .add_modifier(Modifier::BOLD),
        ),
        Tri::Unknown => (
            "?",
            Style::new()
                .fg(Color::Black)
                .bg(AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Tri::No => ("no", Style::new().fg(Color::Black).bg(GREEN)),
    }
}

// ---------- Header ----------

/// Title row and status row.
fn render_header(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let [top, bottom] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let badge = link_badge(&view.link);
    let badge_width = u16::try_from(badge.width()).unwrap_or(u16::MAX);
    let [title, link] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(badge_width)]).areas(top);
    frame.render_widget(Paragraph::new(title_line(state)), title);
    frame.render_widget(Paragraph::new(Line::from(badge)), link);
    frame.render_widget(Paragraph::new(status_line(state)), bottom);
}

/// `CLEANROOM  INC-7 Ransomware on acme-fs  ANALYZING  CRITICAL`.
fn title_line(state: &State) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            " CLEANROOM ",
            Style::new().fg(Color::Black).bg(Color::White).bold(),
        ),
        Span::raw(" "),
    ];
    match &state.incident {
        None => spans.push(Span::styled("No incident declared", Style::new().fg(GRAY))),
        Some(incident) => {
            spans.push(Span::styled(
                incident.id.clone(),
                Style::new().fg(GRAY).bold(),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                incident.title.clone(),
                Style::new().fg(Color::White).bold(),
            ));
            spans.push(Span::raw("  "));
            spans.push(status_badge(incident.status));
            spans.push(Span::raw(" "));
            spans.push(severity_badge(incident.severity));
        }
    }
    Line::from(spans)
}

/// Guardrails, receipt log, block counters and model mode.
fn status_line(state: &State) -> Line<'static> {
    let guardrails = if state.guardrails {
        Span::styled(
            " GUARDRAILS ON ",
            Style::new().fg(Color::Black).bg(GREEN).bold(),
        )
    } else {
        Span::styled(
            " GUARDRAILS OFF ",
            Style::new().fg(Color::White).bg(RED).bold(),
        )
    };
    let log = match state.log {
        LogStatus::Unverified => Span::styled(" LOG not verified (v) ", Style::new().fg(GRAY)),
        LogStatus::Intact { entries } => Span::styled(
            format!(" LOG ✓ {entries} receipts intact "),
            Style::new().fg(Color::Black).bg(GREEN).bold(),
        ),
        LogStatus::Broken { first_break, .. } => Span::styled(
            format!(" LOG BROKEN at #{first_break} "),
            Style::new().fg(Color::White).bg(RED).bold(),
        ),
    };
    let mut spans = vec![guardrails, Span::raw(" "), log];
    match state.counters {
        None => spans.push(Span::raw("  Blocked by model –  by OS –").fg(GRAY)),
        Some(counters) => {
            spans.extend([
                Span::raw("  Blocked by model ").fg(GRAY),
                Span::styled(
                    counters.blocked_by_model.to_string(),
                    Style::new().fg(Color::White).bold(),
                ),
                Span::raw("  by OS ").fg(GRAY),
                Span::styled(
                    counters.blocked_by_os.to_string(),
                    Style::new().fg(BRIGHT_RED).bold(),
                ),
                Span::raw("  Safety flags ").fg(GRAY),
                Span::styled(
                    counters.safety_flags.to_string(),
                    Style::new().fg(AMBER).bold(),
                ),
                Span::raw("  "),
                llm_badge(counters.llm),
            ]);
        }
    }
    Line::from(spans)
}

/// Where the agents' model responses come from. A replay is labelled loudly: the demo must
/// never pass recorded model output off as live.
fn llm_badge(llm: LlmMode) -> Span<'static> {
    match llm {
        LlmMode::Live => Span::raw("LLM live").fg(GRAY),
        LlmMode::Record => Span::styled("LLM live, recording", Style::new().fg(AMBER).bold()),
        LlmMode::Replay => Span::styled(
            " LLM REPLAY ",
            Style::new().fg(Color::Black).bg(AMBER).bold(),
        ),
    }
}

/// LIVE / DISCONNECTED / REPLAY badge.
fn link_badge(link: &Link) -> Span<'static> {
    match link {
        Link::Live { down: None } => {
            Span::styled(" ● LIVE ", Style::new().fg(Color::Black).bg(GREEN).bold())
        }
        Link::Live { down: Some(_) } => Span::styled(
            " ✗ DISCONNECTED ",
            Style::new().fg(Color::White).bg(RED).bold(),
        ),
        Link::Replay {
            speed,
            finished: false,
        } => Span::styled(
            format!(" ▶ REPLAY {speed}× "),
            Style::new().fg(Color::Black).bg(AMBER).bold(),
        ),
        Link::Replay { finished: true, .. } => Span::styled(
            " ■ REPLAY ENDED ",
            Style::new().fg(Color::Black).bg(AMBER).bold(),
        ),
    }
}

/// Incident lifecycle badge.
fn status_badge(status: IncidentStatus) -> Span<'static> {
    let (fg, bg) = match status {
        IncidentStatus::Detected => (Color::White, RED),
        IncidentStatus::Analyzing => (Color::Black, AMBER),
        IncidentStatus::Contained => (Color::Black, BLUE),
        IncidentStatus::Eradicated | IncidentStatus::Recovered => (Color::Black, GREEN),
        IncidentStatus::Closed => (Color::Black, GRAY),
    };
    let word = crate::state::status_word(status).to_uppercase();
    Span::styled(format!(" {word} "), Style::new().fg(fg).bg(bg).bold())
}

/// Severity badge.
fn severity_badge(severity: Severity) -> Span<'static> {
    let (word, fg, bg) = match severity {
        Severity::Critical => ("CRITICAL", Color::White, RED),
        Severity::High => ("HIGH", Color::Black, Color::Indexed(209)),
        Severity::Moderate => ("MODERATE", Color::Black, AMBER),
        Severity::Low => ("LOW", Color::Black, GREEN),
    };
    Span::styled(format!(" {word} "), Style::new().fg(fg).bg(bg).bold())
}

// ---------- Legal clocks ----------

/// Five boxed clocks: countdown on top, deadline or reason below.
fn render_clock_boxes(
    frame: &mut Frame<'_>,
    area: Rect,
    all: &[Clock; 5],
    now: Timestamp,
    tz: &TimeZone,
) {
    let cells: [Rect; 5] = Layout::horizontal([Constraint::Ratio(1, 5); 5]).areas(area);
    for (clock, cell) in all.iter().zip(cells) {
        let (main, detail, color) = clock_text(clock, now, tz);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(color))
            .title(Line::from(format!(" {} ", clock.regime.label())).bold());
        let lines = vec![
            Line::from(main).bold().fg(color).centered(),
            Line::from(detail).fg(GRAY).centered(),
        ];
        frame.render_widget(Paragraph::new(lines).block(block), cell);
    }
}

/// All clocks on one line, for short terminals.
fn render_clock_line(frame: &mut Frame<'_>, area: Rect, all: &[Clock; 5], now: Timestamp) {
    let mut spans = Vec::new();
    for clock in all {
        let (main, _, color) = clock_text(clock, now, &TimeZone::UTC);
        if !spans.is_empty() {
            spans.push(Span::raw(" │ ").fg(BORDER));
        }
        spans.push(Span::raw(format!("{} ", clock.regime.short_label())).fg(GRAY));
        spans.push(Span::styled(main, Style::new().fg(color).bold()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Countdown, detail line and color for one clock.
fn clock_text(clock: &Clock, now: Timestamp, tz: &TimeZone) -> (String, String, Color) {
    match &clock.state {
        ClockState::NotStarted => ("not started".to_owned(), "trigger not set".to_owned(), GRAY),
        ClockState::NotApplicable(reason) => ("n/a".to_owned(), reason.clone(), GRAY),
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

/// Color of a running clock.
const fn urgency_color(urgency: Urgency) -> Color {
    match urgency {
        Urgency::Calm => Color::White,
        Urgency::Soon => AMBER,
        Urgency::Urgent | Urgency::Overdue => BRIGHT_RED,
    }
}

/// `due` in the display zone with a strftime `format`.
fn due_label(due: Timestamp, tz: &TimeZone, format: &str) -> String {
    let local = due.to_zoned(tz.clone());
    strtime::format(format, &local).unwrap_or_else(|_| local.to_string())
}

// ---------- What do I do now ----------

/// The one-line next step, plus the latest notice.
fn render_now(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let action = next::next_action(state, view.connected(), now);
    let (text, color) = action_text(&action, view, &state.display_tz);
    let notice = state.notice.as_ref().map_or_else(
        || Line::from("No messages yet.").fg(GRAY),
        |notice| {
            Line::from(vec![
                Span::raw("Last: ").fg(GRAY),
                Span::styled(
                    notice.text.clone(),
                    Style::new().fg(tone_color(notice.tone)),
                ),
            ])
        },
    );
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::new().fg(color))
        .title(Line::from(" WHAT DO I DO NOW ").bold().fg(color));
    let lines = vec![
        Line::from(vec![
            Span::styled("▶ ", Style::new().fg(color).bold()),
            Span::styled(text, Style::new().fg(color).bold()),
        ]),
        notice,
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Sentence and color for the next action.
fn action_text(action: &NextAction, view: &View, tz: &TimeZone) -> (String, Color) {
    match action {
        NextAction::Reconnect => {
            let reason = match &view.link {
                Link::Live { down: Some(reason) } => reason.as_str(),
                Link::Live { down: None } | Link::Replay { .. } => "connection lost",
            };
            (
                format!("Lost cleanroomd ({reason}). Restart it, then relaunch this console. q quits."),
                BRIGHT_RED,
            )
        }
        NextAction::LogBroken { first_break } => (
            format!(
                "Receipt log broken at entry {first_break}. Preserve the log file and tell counsel before anything else."
            ),
            BRIGHT_RED,
        ),
        NextAction::Approvals { count } => {
            let noun = if *count == 1 { "approval" } else { "approvals" };
            (
                format!("{count} {noun} waiting. ↑↓ pick one, then a approves or x denies."),
                AMBER,
            )
        }
        NextAction::Clock {
            regime,
            remaining,
            due,
            urgency,
        } => (clock_sentence(*regime, *remaining, *due, tz), urgency_color(*urgency)),
        NextAction::Investigate => (
            "Incident declared. Press i to start the agent team on it.".to_owned(),
            AMBER,
        ),
        NextAction::Detonate => match view.link {
            Link::Replay { .. } => ("All clear so far. The recording continues…".to_owned(), GREEN),
            Link::Live { .. } => (
                "All clear. Press d to detonate a scenario in the sacrificial stratum.".to_owned(),
                GREEN,
            ),
        },
        NextAction::Watch => (
            "Nothing needs you right now. Agents are investigating; watch scope and the agent pane."
                .to_owned(),
            GREEN,
        ),
    }
}

/// `Texas AG notice due in 29d (Mon Dec 7). File the notice with the Texas Attorney General.`
fn clock_sentence(
    regime: clocks::Regime,
    remaining: SignedDuration,
    due: Timestamp,
    tz: &TimeZone,
) -> String {
    let notice = regime.notice();
    let duty = regime.duty();
    if remaining.is_negative() {
        let late = clocks::short_remaining(remaining.abs());
        format!("{notice} OVERDUE by {late}. {duty}")
    } else {
        let left = clocks::short_remaining(remaining);
        let day = due_label(due, tz, "%a %b %-d");
        format!("{notice} due in {left} ({day}). {duty}")
    }
}

// ---------- Body ----------

/// Scope across the top; agents, approvals, timeline and comms below.
fn render_body(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let rows = u16::try_from(state.scope.len()).unwrap_or(u16::MAX);
    let scope_height = rows.saturating_add(3).clamp(4, (area.height / 2).max(4));
    let [scope, lower] =
        Layout::vertical([Constraint::Length(scope_height), Constraint::Fill(1)]).areas(area);
    render_scope(frame, scope, state);
    let queue_rows = u16::try_from(state.queue.len().max(1) * 2).unwrap_or(u16::MAX);
    if area.width >= 110 {
        let [agents, side] =
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                .areas(lower);
        let queue_height = queue_rows
            .saturating_add(2)
            .clamp(3, (side.height / 2).max(3));
        let [approvals, timeline, comms] = Layout::vertical([
            Constraint::Length(queue_height),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .areas(side);
        render_agents(frame, agents, state);
        render_approvals(frame, approvals, state, view);
        render_timeline(frame, timeline, state);
        render_comms(frame, comms, state);
    } else {
        let queue_height = queue_rows
            .saturating_add(2)
            .clamp(3, (lower.height / 2).max(3));
        let [approvals, agents, comms] = Layout::vertical([
            Constraint::Length(queue_height),
            Constraint::Fill(2),
            Constraint::Fill(1),
        ])
        .areas(lower);
        render_approvals(frame, approvals, state, view);
        render_agents(frame, agents, state);
        render_comms(frame, comms, state);
    }
}

/// A titled panel.
fn panel(title: String) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(title).bold())
}

/// The scope table: one row per asset, one colored cell per flag.
fn render_scope(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let records = state
        .scope
        .iter()
        .map(|asset| asset.record_count)
        .fold(0, u64::saturating_add);
    let texans = clocks::texas_residents(&state.scope);
    let block = panel(format!(
        " SCOPE OF COMPROMISED DATA · {} assets · {} records · {} Texans ",
        state.scope.len(),
        grouped(records),
        grouped(texans)
    ));
    if state.scope.is_empty() {
        let hint = "No assets reported yet. cleanroomd publishes the asset table; press d to detonate a scenario.";
        frame.render_widget(Paragraph::new(hint).fg(GRAY).block(block), area);
        return;
    }
    let names = if area.width >= 120 {
        ["LOCKED", "EXFILTRATED", "ACCESSED", "DESTROYED", "MODIFIED"]
    } else {
        ["LCK", "EXF", "ACC", "DST", "MOD"]
    };
    let flag_width = if area.width >= 120 { 11 } else { 4 };
    let mut header = vec![
        Cell::from("ASSET"),
        Cell::from("CLASSES"),
        Cell::from(Line::from("RECORDS").right_aligned()),
        Cell::from(Line::from("TEXANS").right_aligned()),
    ];
    header.extend(names.map(|name| Cell::from(Line::from(name).centered())));
    header.push(Cell::from(Line::from("CONF").right_aligned()));
    let mut widths = vec![
        Constraint::Fill(3),
        Constraint::Fill(2),
        Constraint::Length(9),
        Constraint::Length(7),
    ];
    widths.extend([Constraint::Length(flag_width); 5]);
    widths.push(Constraint::Length(5));
    let table = Table::new(state.scope.iter().map(scope_row), widths)
        .header(Row::new(header).style(Style::new().fg(GRAY).bold()))
        .column_spacing(1)
        .block(block);
    frame.render_widget(table, area);
}

/// One asset row.
fn scope_row(asset: &ScopeRecord) -> Row<'static> {
    let classes = asset
        .data_classes
        .iter()
        .map(|class| class_label(*class))
        .collect::<Vec<_>>()
        .join(", ");
    let flags = &asset.flags;
    let mut cells = vec![
        Cell::from(asset.name.clone()).style(Style::new().fg(Color::White).bold()),
        Cell::from(classes),
        Cell::from(Line::from(grouped(asset.record_count)).right_aligned()),
        Cell::from(Line::from(grouped(asset.texas_residents)).right_aligned()),
    ];
    cells.extend(
        [
            flags.locked,
            flags.exfiltrated,
            flags.accessed,
            flags.destroyed,
            flags.modified,
        ]
        .map(|value| {
            let (word, style) = flag_look(value);
            Cell::from(Line::from(word).centered()).style(style)
        }),
    );
    cells.push(Cell::from(
        Line::from(format!("{}%", asset.confidence_pct)).right_aligned(),
    ));
    Row::new(cells)
}

/// Display name of a data class.
const fn class_label(class: DataClass) -> &'static str {
    match class {
        DataClass::Pii => "PII",
        DataClass::Phi => "PHI",
        DataClass::Financial => "financial",
        DataClass::Contracts => "contracts",
        DataClass::Credentials => "credentials",
        DataClass::Other => "other",
    }
}

/// The live agent pane, newest at the bottom.
fn render_agents(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let block = panel(" AGENTS · live trace ".to_owned());
    if state.activity.is_empty() {
        let hint = "Agents are idle. They start when an incident is declared, or press i.";
        frame.render_widget(Paragraph::new(hint).fg(GRAY).block(block), area);
        return;
    }
    let inner = block.inner(area);
    let lines = tail(
        state.activity.iter().map(activity_entry),
        usize::from(inner.width),
        usize::from(inner.height),
    );
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// `20:14:05 ▌HUNTER      BLOCKED BY OS #5 exec rm -rf /evidence/* → denied: …`.
fn activity_entry(activity: &Activity) -> LogEntry {
    let color = who_color(&activity.who);
    let text = match activity.tone {
        Tone::Bad => BRIGHT_RED,
        Tone::Quiet => GRAY,
        Tone::Plain | Tone::Good | Tone::Warn => Color::White,
    };
    LogEntry {
        prefix: vec![
            Span::raw(activity.at.clone()).fg(GRAY),
            Span::raw(" ▌").fg(color),
            Span::styled(
                format!("{:<11}", who_label(&activity.who)),
                Style::new().fg(color).bold(),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{:<13}", activity.tag),
                Style::new().fg(tone_color(activity.tone)).bold(),
            ),
            Span::raw(" "),
        ],
        text: activity.text.clone(),
        style: Style::new().fg(text),
    }
}

/// Pending tool requests and proposals, two lines each, with the selected one marked.
fn render_approvals(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let waiting = state.waiting();
    let (title, color) = if waiting > 0 {
        (
            format!(" APPROVALS · {waiting} waiting · a approve · x deny "),
            AMBER,
        )
    } else {
        (" APPROVALS ".to_owned(), BORDER)
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(
            Line::from(title)
                .bold()
                .fg(if waiting > 0 { AMBER } else { Color::White }),
        );
    if state.queue.is_empty() {
        frame.render_widget(
            Paragraph::new("Nothing waiting for your signature.")
                .fg(GRAY)
                .block(block),
            area,
        );
        return;
    }
    let fits = (usize::from(block.inner(area).height) / 2).max(1);
    let first = view.selected.saturating_sub(fits - 1);
    let lines: Vec<Line<'static>> = state
        .queue
        .iter()
        .enumerate()
        .skip(first)
        .take(fits)
        .flat_map(|(index, item)| queue_lines(item, index == view.selected))
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// One queued item: who wants what, then the reason and the subject id.
fn queue_lines(item: &QueueItem, selected: bool) -> [Line<'static>; 2] {
    let (kind, headline, detail) = match &item.ask {
        Ask::Tool {
            tool,
            source,
            reason,
        } => (
            "TOOL",
            format!("wants {tool}"),
            format!("{reason} · {source}"),
        ),
        Ask::Proposal { action, rationale } => ("ACTION", action.clone(), rationale.clone()),
    };
    let mut first = vec![
        Span::styled(
            if selected { "▶ " } else { "  " },
            Style::new().fg(AMBER).bold(),
        ),
        Span::styled(
            format!(" {kind} "),
            Style::new().fg(Color::Black).bg(AMBER).bold(),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{} ", who_label(&item.from)),
            Style::new().fg(who_color(&item.from)).bold(),
        ),
        Span::styled(headline, Style::new().fg(Color::White).bold()),
    ];
    match item.sent {
        None => {}
        Some(true) => first.push(Span::styled(
            "  approved, confirming…",
            Style::new().fg(GREEN),
        )),
        Some(false) => first.push(Span::styled(
            "  denied, confirming…",
            Style::new().fg(BRIGHT_RED),
        )),
    }
    let second = Line::from(vec![
        Span::raw("    "),
        Span::raw(format!("{detail} · {}", item.subject_id)).fg(GRAY),
    ]);
    let first = Line::from(first);
    if selected {
        [first.bg(SELECTED_BG), second.bg(SELECTED_BG)]
    } else {
        [first, second]
    }
}

/// The incident record's timeline.
fn render_timeline(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let block = panel(" INCIDENT TIMELINE ".to_owned());
    let entries = state
        .incident
        .as_ref()
        .map(|incident| incident.timeline.as_slice())
        .unwrap_or_default();
    if entries.is_empty() {
        let hint = if state.incident.is_some() {
            "Scribe has not written the timeline yet."
        } else {
            "No incident record yet."
        };
        frame.render_widget(Paragraph::new(hint).fg(GRAY).block(block), area);
        return;
    }
    let inner = block.inner(area);
    let log = entries.iter().map(|entry| {
        let who = state.who(&entry.by);
        let evidence = match entry.evidence.len() {
            0 => String::new(),
            count => format!(" [{count} ev]"),
        };
        LogEntry {
            prefix: vec![
                Span::raw(state.time_label(&entry.at)).fg(GRAY),
                Span::raw(" "),
                Span::styled(
                    format!("{} ", who_label(&who)),
                    Style::new().fg(who_color(&who)),
                ),
            ],
            text: format!("{}{evidence}", entry.text),
            style: Style::new().fg(Color::White),
        }
    });
    let lines = tail(log, usize::from(inner.width), usize::from(inner.height));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Human chat on the bus.
fn render_comms(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let block = panel(" COMMS · c to write ".to_owned());
    if state.chat.is_empty() {
        frame.render_widget(
            Paragraph::new("No messages. Press c to write to the team.")
                .fg(GRAY)
                .block(block),
            area,
        );
        return;
    }
    let inner = block.inner(area);
    let log = state.chat.iter().map(|line| LogEntry {
        prefix: vec![
            Span::raw(line.at.clone()).fg(GRAY),
            Span::raw(" "),
            Span::styled(
                format!("{}: ", who_label(&line.who)),
                Style::new().fg(who_color(&line.who)).bold(),
            ),
        ],
        text: line.text.clone(),
        style: Style::new().fg(Color::White),
    });
    let lines = tail(log, usize::from(inner.width), usize::from(inner.height));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// One entry of a wrapped log pane: fixed prefix columns, then text that wraps under itself.
#[derive(Debug)]
struct LogEntry {
    /// Time, sender and tag columns.
    prefix: Vec<Span<'static>>,
    /// The entry's text.
    text: String,
    /// Style of the text.
    style: Style,
}

/// The newest entries that fit in `rows` lines of `width` columns, oldest first.
///
/// Each entry wraps with a hanging indent, so the prefix columns stay scannable and long
/// results (a denial reason, a ransom note excerpt) are never cut off. An older entry that
/// would only partly fit is left out, and blank lines keep the newest entry at the bottom.
fn tail<I>(entries: I, width: usize, rows: usize) -> Vec<Line<'static>>
where
    I: DoubleEndedIterator<Item = LogEntry>,
{
    let mut newest_first = Vec::with_capacity(rows);
    for entry in entries.rev() {
        let room = rows.saturating_sub(newest_first.len());
        if room == 0 {
            break;
        }
        let indent: usize = entry.prefix.iter().map(Span::width).sum();
        let mut prefix = Some(entry.prefix);
        let wrapped: Vec<Line<'static>> = wrap(&entry.text, width.saturating_sub(indent).max(8))
            .into_iter()
            .map(|chunk| {
                let mut spans = prefix
                    .take()
                    .unwrap_or_else(|| vec![Span::raw(" ".repeat(indent))]);
                spans.push(Span::styled(chunk, entry.style));
                Line::from(spans)
            })
            .collect();
        if wrapped.len() > room && !newest_first.is_empty() {
            newest_first.resize_with(rows, Line::default);
            break;
        }
        newest_first.extend(wrapped.into_iter().rev().take(room));
    }
    newest_first.reverse();
    newest_first
}

/// Word-wrap `text` to `width` columns, splitting words longer than a line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for word in text.split(' ') {
        let mut chars: Vec<char> = word.chars().collect();
        if used > 0 && used + 1 + chars.len() > width {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        if used > 0 {
            line.push(' ');
            used += 1;
        }
        while used + chars.len() > width {
            let room = width - used;
            line.extend(chars.drain(..room));
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        used += chars.len();
        line.extend(chars);
    }
    lines.push(line);
    lines
}

/// Persistent key hints, or the chat input line while typing.
fn render_keys(frame: &mut Frame<'_>, area: Rect, view: &View) {
    if let Some(text) = &view.chat {
        let prompt = Span::styled(
            " MESSAGE ",
            Style::new().fg(Color::Black).bg(Color::White).bold(),
        );
        let typed = Span::raw(format!(" {text}"));
        let cursor_x = area
            .x
            .saturating_add(u16::try_from(prompt.width() + typed.width()).unwrap_or(u16::MAX));
        let help = Span::raw("   Enter sends · Esc cancels").fg(GRAY);
        frame.render_widget(Paragraph::new(Line::from(vec![prompt, typed, help])), area);
        frame.set_cursor_position((cursor_x.min(area.right().saturating_sub(1)), area.y));
        return;
    }
    let full = [
        ("d", "Detonate"),
        ("t", "Tamper"),
        ("a", "Approve"),
        ("x", "Deny"),
        ("↑↓", "Select"),
        ("g", "Guardrails"),
        ("i", "Investigate"),
        ("v", "Verify log"),
        ("r", "Reset"),
        ("c", "Chat"),
    ];
    // Narrow terminals keep every action key; the arrows are also named in the
    // approvals title and the "what do I do now" line.
    let compact = [
        ("d", "Detonate"),
        ("t", "Tamper"),
        ("a", "Approve"),
        ("x", "Deny"),
        ("g", "Guard"),
        ("i", "Invest."),
        ("v", "Verify"),
        ("r", "Reset"),
        ("c", "Chat"),
    ];
    let [left, right] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(18)]).areas(area);
    let wide = Line::from(
        full.iter()
            .flat_map(|(key, label)| hint(key, label, 1))
            .collect::<Vec<_>>(),
    );
    let line = if wide.width() <= usize::from(left.width) {
        wide
    } else {
        Line::from(
            compact
                .iter()
                .flat_map(|(key, label)| hint(key, label, 0))
                .collect::<Vec<_>>(),
        )
    };
    frame.render_widget(Paragraph::new(line), left);
    let fixed: Vec<Span<'static>> = [("?", "Help"), ("q", "Quit")]
        .iter()
        .flat_map(|(key, label)| hint(key, label, 1))
        .collect();
    frame.render_widget(Paragraph::new(Line::from(fixed).right_aligned()), right);
}

/// One key badge and its label, with `pad` spaces inside the badge.
fn hint(key: &str, label: &str, pad: usize) -> [Span<'static>; 2] {
    let space = " ".repeat(pad);
    [
        Span::styled(
            format!("{space}{key}{space}"),
            Style::new().fg(Color::Black).bg(Color::Indexed(250)).bold(),
        ),
        Span::raw(format!(" {label} ")),
    ]
}

// ---------- Overlays ----------

/// The open modal, if any. An undismissed admission result wins over everything.
fn render_overlay(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    if view.admission_visible(state)
        && let Some(admission) = &state.admission
    {
        render_admission(frame, area, admission);
        return;
    }
    match view.overlay {
        Overlay::None => {}
        Overlay::Help => render_help(frame, area),
        Overlay::Detonate { cursor } => render_detonate(frame, area, &view.scenarios, cursor),
        Overlay::ConfirmReset => render_confirm_reset(frame, area),
    }
}

/// The tamper beat: a big red refusal naming the layer and both digests.
fn render_admission(frame: &mut Frame<'_>, area: Rect, admission: &Admission) {
    let popup = area.centered(Constraint::Percentage(92), Constraint::Length(15));
    frame.render_widget(Clear, popup);
    let (headline, title, base, details) = match admission {
        Admission::Rejected {
            root,
            layer,
            expected,
            actual,
        } => (
            "REJECTED",
            " ADMISSION REJECTED · tampered root blocked ",
            Style::new().fg(Color::White).bg(RED),
            vec![
                detail("Root", root.clone(), Style::new().bold()),
                detail("Layer", layer.clone(), Style::new().bold()),
                detail("Expected", expected.clone(), Style::new()),
                detail(
                    "Actual",
                    actual.clone(),
                    Style::new().fg(Color::Black).bg(AMBER).bold(),
                ),
                Line::default(),
                Line::from("One byte changed, so the digest changed. The tampered root never ran.")
                    .bold(),
            ],
        ),
        Admission::Admitted { root, manifest } => (
            "ADMITTED",
            " ADMISSION OK · digests match the lock ",
            Style::new().fg(Color::Black).bg(GREEN),
            vec![
                detail("Root", root.clone(), Style::new().bold()),
                detail("Manifest", manifest.clone(), Style::new()),
            ],
        ),
    };
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .style(base)
        .title(Line::from(title).bold())
        .title_bottom(Line::from(" Enter or Esc dismisses ").bold().centered());
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let [big, rest] = Layout::vertical([Constraint::Length(5), Constraint::Fill(1)]).areas(inner);
    let pixels = if big.width >= BIG_TEXT_WIDTH {
        PixelSize::HalfHeight
    } else {
        PixelSize::Quadrant
    };
    let big_text = BigText::builder()
        .pixel_size(pixels)
        .style(base.add_modifier(Modifier::BOLD))
        .lines(vec![Line::from(headline)])
        .centered()
        .build();
    frame.render_widget(big_text, big);
    frame.render_widget(Paragraph::new(details).wrap(Wrap { trim: false }), rest);
}

/// `Label     value` row of the admission panel.
fn detail(label: &str, value: String, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("  {label:<9} ")).bold(),
        Span::styled(value, style),
    ])
}

/// A centered modal with `title` and `lines`.
fn modal(frame: &mut Frame<'_>, area: Rect, title: &str, color: Color, lines: Vec<Line<'static>>) {
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let popup = area.centered(Constraint::Max(84), Constraint::Length(height));
    frame.render_widget(Clear, popup);
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::new().fg(color))
        .title(Line::from(format!(" {title} ")).bold().fg(color));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        popup,
    );
}

/// Key reference.
fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let keys = [
        (
            "d",
            "Detonate a scenario in the sacrificial stratum (asks which)",
        ),
        (
            "t",
            "Tamper demo: flip a byte in a root, then try to admit it",
        ),
        (
            "a / x",
            "Approve / deny the selected item, signed with your key",
        ),
        ("↑ ↓", "Select an approval"),
        ("g", "Toggle agent guardrails (hardened or naive prompts)"),
        ("i", "Start the agent team on the incident"),
        ("v", "Verify the receipt log's hash chain"),
        ("r", "Reset the demo (asks first)"),
        ("c or /", "Write to the team"),
        ("?", "Open or close this help"),
        ("q", "Quit"),
    ];
    let mut lines: Vec<Line<'static>> = keys
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(format!(" {key:<7}"), Style::new().fg(AMBER).bold()),
                Span::raw(*what),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::raw(" Colors: "),
        Span::styled(" YES ", flag_look(Tri::Yes).1),
        Span::raw(" happened / blocked  "),
        Span::styled(" ? ", flag_look(Tri::Unknown).1),
        Span::raw(" unknown / needs you  "),
        Span::styled(" no ", flag_look(Tri::No).1),
        Span::raw(" ruled out / fine"),
    ]));
    lines.push(Line::from(" Esc or ? closes this help.").fg(GRAY));
    modal(frame, area, "KEYS", Color::White, lines);
}

/// Scenario picker for `d`.
fn render_detonate(frame: &mut Frame<'_>, area: Rect, scenarios: &[String], cursor: usize) {
    let mut lines: Vec<Line<'static>> = scenarios
        .iter()
        .enumerate()
        .map(|(index, name)| {
            if index == cursor {
                Line::from(format!(" ▶ {name} "))
                    .fg(Color::Black)
                    .bg(AMBER)
                    .bold()
            } else {
                Line::from(format!("   {name}"))
            }
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(
        " Runs inside the acme-fs stratum: no network, nothing leaves the sandbox.",
    ));
    lines.push(Line::from(" ↑↓ choose · Enter detonates · Esc cancels").fg(GRAY));
    modal(frame, area, "DETONATE WHICH SCENARIO?", AMBER, lines);
}

/// Confirmation for `r`.
fn render_confirm_reset(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(" Reset the demo? cleanroomd resets the strata and this console clears."),
        Line::default(),
        Line::from(" y resets · n or Esc cancels").fg(GRAY),
    ];
    modal(frame, area, "RESET", BRIGHT_RED, lines);
}

// ---------- Shared pieces ----------

/// Sender label, at most 11 columns so the agent pane's columns line up.
fn who_label(who: &Who) -> String {
    match who {
        Who::Agent(role) => role_label(*role).to_owned(),
        Who::System => "SYSTEM".to_owned(),
        Who::Me => "YOU".to_owned(),
        Who::Human(short) => format!("HUMAN {}", short.chars().take(5).collect::<String>()),
    }
}

/// Upper-case role name.
const fn role_label(role: cleanroom_proto::Role) -> &'static str {
    match role {
        cleanroom_proto::Role::Hunter => "HUNTER",
        cleanroom_proto::Role::Forensics => "FORENSICS",
        cleanroom_proto::Role::Scribe => "SCRIBE",
        cleanroom_proto::Role::Containment => "CONTAINMENT",
    }
}

/// Role colors stay clear of red, amber and green, which carry status meaning.
const fn who_color(who: &Who) -> Color {
    match who {
        Who::Agent(cleanroom_proto::Role::Hunter) => Color::Indexed(51),
        Who::Agent(cleanroom_proto::Role::Forensics) => Color::Indexed(177),
        Who::Agent(cleanroom_proto::Role::Scribe) => Color::Indexed(111),
        Who::Agent(cleanroom_proto::Role::Containment) => Color::Indexed(218),
        Who::System => Color::Indexed(250),
        Who::Me | Who::Human(_) => Color::White,
    }
}

/// Color for a tone.
const fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Quiet => GRAY,
        Tone::Plain => Color::White,
        Tone::Good => GREEN,
        Tone::Warn => AMBER,
        Tone::Bad => BRIGHT_RED,
    }
}

/// `12,480`.
fn grouped(value: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_flags_map_yes_to_red_unknown_to_amber_and_no_to_green() {
        let (yes, yes_style) = flag_look(Tri::Yes);
        let (unknown, unknown_style) = flag_look(Tri::Unknown);
        let (no, no_style) = flag_look(Tri::No);
        assert_eq!((yes, yes_style.bg), ("YES", Some(RED)));
        assert_eq!((unknown, unknown_style.bg), ("?", Some(AMBER)));
        assert_eq!((no, no_style.bg), ("no", Some(GREEN)));
    }
}
