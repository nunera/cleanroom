//! The Controlroom screen: the dense operator view.
//!
//! Every OS denial is pinned in a strip at the top so it never scrolls away; below it sit the
//! legal clocks, the next step, the scope table, the agent trace (one line per step; the selected
//! step expands), approvals, the incident timeline and comms.

use cleanroom_proto::{Audience, DataClass, ScopeRecord};
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table};

use super::{
    Focus, Link, Pane, View, clock_text, due_label, fit, flag_look, grouped, pad, panel,
    role_label, spaces, title, tone_color, urgency_color, who_color, who_label, width_of, wrap,
};
use crate::clocks::{self, Clock};
use crate::denials::{Denial, Kind};
use crate::next::{self, NextAction};
use crate::state::{Activity, Ask, QueueItem, State, Talk, Tone, audience_title};
use crate::team;
use crate::theme::{ACCENT, AMBER, BRIGHT, DIM, LINE, MUTED, RAISED_HI, RED, TEXT, glyph, tint};

/// Draw the screen into `area`, everything between the top bar and the hint bar.
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let [_, inner, _] = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let compact = inner.height < 34;
    let most = if compact { 2 } else { 4 };
    let strip_rows = state.denials.len().clamp(1, most);
    let strip_height = u16::try_from(strip_rows).unwrap_or(1).saturating_add(2);
    let [strip, clock_area, next_area, body] = Layout::vertical([
        Constraint::Length(strip_height),
        Constraint::Length(if compact { 1 } else { 4 }),
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .areas(inner);
    render_strip(frame, strip, state);
    let all = clocks::clocks(&state.triggers(), &state.scope);
    if compact {
        render_clock_line(frame, clock_area, &all, now);
    } else {
        render_clock_boxes(frame, clock_area, &all, now, &state.display_tz);
    }
    render_next(frame, next_area, state, view, now);
    render_body(frame, body, state, view);
}

// ---------- Pinned OS denials ----------

/// Every OS denial of the session, newest last, pinned so it never scrolls away.
fn render_strip(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let denials = state.denials.all();
    let shown = usize::from(area.height.saturating_sub(2)).max(1);
    let earlier = denials.len().saturating_sub(shown);
    let (title_text, color) = if denials.is_empty() {
        (" BLOCKED BY OS · none yet ".to_owned(), LINE)
    } else {
        let noun = if denials.len() == 1 {
            "denial"
        } else {
            "denials"
        };
        let more = if earlier > 0 {
            format!(" · {earlier} earlier not shown")
        } else {
            String::new()
        };
        (
            format!(
                " ⛔ BLOCKED BY OS · {} {noun} · pinned{more} ",
                denials.len()
            ),
            RED,
        )
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(
            Line::from(title_text)
                .fg(if denials.is_empty() { MUTED } else { RED })
                .bold(),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if denials.is_empty() {
        let hint = "Every agent command runs under its stratum's grant. A denial lands here with its signed receipt.";
        frame.render_widget(
            Paragraph::new(fit(hint, usize::from(inner.width).saturating_sub(1))).fg(DIM),
            inner,
        );
        return;
    }
    let width = usize::from(inner.width);
    let lines: Vec<Line<'static>> = denials
        .iter()
        .skip(earlier)
        .map(|denial| denial_line(denial, width))
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// `04:39:30  ▲ HUNTER      #5 exec rm -rf /evidence/*      read-only    receipt #15`.
fn denial_line(denial: &Denial, width: usize) -> Line<'static> {
    let who = denial.role.map_or_else(
        || Span::raw(pad(&denial.who.to_uppercase(), 13)).fg(MUTED),
        |role| Span::raw(pad(&format!("{} {}", glyph(role), role_label(role)), 13)).fg(tint(role)),
    );
    let step = denial
        .step
        .map(|step| format!("#{step} "))
        .unwrap_or_default();
    let action = match denial.kind {
        Kind::Exec => format!("{step}exec {}", denial.command),
        Kind::Record => format!("{step}record: {}", denial.command),
    };
    let reason = fit(&denial.short_reason(), 22);
    let receipt = denial.receipt.map_or_else(
        || "receipt pending".to_owned(),
        |seq| format!("receipt #{seq}"),
    );
    let time = format!(" {}  ", denial.at);
    let fixed = width_of(&time) + 14 + 2 + 24 + width_of(&receipt) + 1;
    let action = pad(&action, width.saturating_sub(fixed));
    Line::from(vec![
        Span::raw(time).fg(DIM),
        who,
        Span::raw(" "),
        Span::raw(action).fg(BRIGHT).bold(),
        Span::raw("  "),
        Span::raw(pad(&reason, 24)).fg(RED).bold(),
        Span::raw(receipt).fg(MUTED),
    ])
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
    let cells: [Rect; 5] = Layout::horizontal([Constraint::Ratio(1, 5); 5])
        .spacing(1)
        .areas(area);
    for (clock, cell) in all.iter().zip(cells) {
        let (main, detail, color) = clock_text(clock, now, tz);
        let border = if color == DIM { LINE } else { color };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border))
            .title(
                Line::from(format!(" {} ", clock.regime.label()))
                    .fg(MUTED)
                    .bold(),
            );
        let lines = vec![
            Line::from(main).bold().fg(color).centered(),
            Line::from(detail).fg(DIM).centered(),
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
            spans.push(Span::raw("  │  ").fg(LINE));
        }
        spans.push(Span::raw(format!("{} ", clock.regime.short_label())).fg(MUTED));
        spans.push(Span::styled(main, Style::new().fg(color).bold()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ---------- What do I do now ----------

/// The one-line next step, plus the latest notice.
fn render_next(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let action = next::next_action(state, view.connected(), now);
    let (text, color) = action_text(&action, view, &state.display_tz);
    let notice = state.notice.as_ref().map_or_else(
        || Line::from("   No messages yet.").fg(DIM),
        |notice| {
            Line::from(vec![
                Span::raw("   ↳ ").fg(DIM),
                Span::raw(notice.text.clone()).fg(tone_color(notice.tone)),
            ])
        },
    );
    let lines = vec![
        Line::from(vec![
            Span::raw(" ▶ ").fg(color).bold(),
            Span::raw(text).fg(color).bold(),
        ]),
        notice,
    ];
    frame.render_widget(Paragraph::new(lines), area);
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
                format!(
                    "Lost cleanroomd ({reason}). Restart it, then relaunch this console. q quits."
                ),
                RED,
            )
        }
        NextAction::LogBroken { first_break } => (
            format!(
                "Receipt log broken at entry {first_break}. Preserve the log file and tell counsel before anything else."
            ),
            RED,
        ),
        NextAction::Readmit { root } => (
            format!(
                "Tampered {root} root was rejected and never ran. Press A (Shift+A) to admit the clean copy."
            ),
            AMBER,
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
        } => (
            clock_sentence(*regime, *remaining, *due, tz),
            urgency_color(*urgency),
        ),
        NextAction::Investigate => (
            "Incident declared. Press i to start the agent team on it.".to_owned(),
            AMBER,
        ),
        NextAction::Detonate => match view.link {
            Link::Replay { .. } => (
                "All clear so far. The recording continues…".to_owned(),
                ACCENT,
            ),
            Link::Live { .. } => (
                "All clear. Press d to detonate a scenario in the sacrificial stratum.".to_owned(),
                ACCENT,
            ),
        },
        NextAction::Watch => (
            "Nothing needs you right now. Agents are investigating; watch scope and the trace."
                .to_owned(),
            ACCENT,
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

/// Scope across the top; the trace, approvals, timeline and comms below.
fn render_body(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let rows = u16::try_from(state.scope.len()).unwrap_or(u16::MAX);
    let scope_height = rows.saturating_add(3).clamp(4, (area.height / 2).max(4));
    let [scope, lower] =
        Layout::vertical([Constraint::Length(scope_height), Constraint::Fill(1)]).areas(area);
    render_scope(frame, scope, state);
    let queue_rows = u16::try_from(state.queue.len().max(1) * 2).unwrap_or(u16::MAX);
    if area.width >= 110 {
        let [agents, _, side] = Layout::horizontal([
            Constraint::Percentage(62),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
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
        render_trace(frame, agents, state, view);
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
        render_trace(frame, agents, state, view);
        render_comms(frame, comms, state);
    }
}

/// The scope table: one row per asset, one colored cell per flag.
fn render_scope(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let records = state
        .scope
        .iter()
        .map(|asset| asset.record_count)
        .fold(0, u64::saturating_add);
    let texans = clocks::texas_residents(&state.scope);
    let block = panel(
        title(
            &format!(
                "SCOPE OF COMPROMISED DATA · {} assets · {} records · {} Texans",
                state.scope.len(),
                grouped(records),
                grouped(texans)
            ),
            false,
        ),
        false,
    );
    if state.scope.is_empty() {
        let hint = "No assets reported yet. cleanroomd publishes the asset table; press d to detonate a scenario.";
        frame.render_widget(Paragraph::new(hint).fg(DIM).block(block), area);
        return;
    }
    let wide = area.width >= 120;
    let names = if wide {
        ["LOCKED", "EXFILTRATED", "ACCESSED", "DESTROYED", "MODIFIED"]
    } else {
        ["LCK", "EXF", "ACC", "DST", "MOD"]
    };
    let flag_width = if wide { 11 } else { 4 };
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
        .header(Row::new(header).style(Style::new().fg(DIM).bold()))
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
        Cell::from(asset.name.clone()).style(Style::new().fg(BRIGHT).bold()),
        Cell::from(classes).style(Style::new().fg(MUTED)),
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

// ---------- Agent trace ----------

/// The live agent trace, one line per step, newest at the bottom. The selected step expands
/// to its full arguments and result.
fn render_trace(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let focused = view.pane == Pane::Trace && view.focus == Focus::Keys;
    let heading = match view.trace {
        Some(_) => "AGENT TRACE · ↑↓ step · Esc follows the newest",
        None => "AGENT TRACE · live",
    };
    let block = panel(title(heading, focused), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if state.activity.is_empty() {
        let hint = "Agents are idle. They start when an incident is declared, or press i.";
        frame.render_widget(Paragraph::new(hint).fg(DIM), inner);
        return;
    }
    let lines = trace_lines(
        state,
        view.trace,
        usize::from(inner.width),
        usize::from(inner.height),
    );
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The trace lines that fit `rows`: the newest, or a window around the selected step.
fn trace_lines(
    state: &State,
    selected: Option<usize>,
    width: usize,
    rows: usize,
) -> Vec<Line<'static>> {
    let total = state.activity.len();
    let Some(selected) = selected.map(|index| index.min(total.saturating_sub(1))) else {
        let mut lines: Vec<Line<'static>> = state
            .activity
            .iter()
            .skip(total.saturating_sub(rows))
            .map(|activity| activity_line(activity, width))
            .collect();
        let mut padded = vec![Line::default(); rows.saturating_sub(lines.len())];
        padded.append(&mut lines);
        return padded;
    };
    let Some(chosen) = state.activity.get(selected) else {
        return Vec::new();
    };
    let mut expanded = expanded_lines(chosen, width);
    expanded.truncate(rows);
    let budget = rows.saturating_sub(expanded.len());
    let after = (total - 1 - selected).min(budget / 2);
    let before = (budget - after).min(selected);
    let mut lines: Vec<Line<'static>> = state
        .activity
        .iter()
        .skip(selected - before)
        .take(before)
        .map(|activity| activity_line(activity, width))
        .collect();
    lines.extend(expanded);
    lines.extend(
        state
            .activity
            .iter()
            .skip(selected + 1)
            .take(after)
            .map(|activity| activity_line(activity, width)),
    );
    lines
}

/// `20:14:05 ▲ HUNTER      BLOCKED BY OS  #5 exec rm -rf /evidence/* → BLOCKED (read-only)`,
/// cut to one line.
fn activity_line(activity: &Activity, width: usize) -> Line<'static> {
    let prefix = activity_prefix(activity, width);
    let used: usize = prefix.iter().map(Span::width).sum();
    let mut spans = prefix;
    spans.push(
        Span::raw(fit(&activity.text, width.saturating_sub(used)))
            .fg(activity_color(activity.tone)),
    );
    Line::from(spans)
}

/// Time, sender and tag columns. A pane narrower than [`NARROW`] keeps the sender's glyph and a
/// short tag, so the step itself still fits on its line.
fn activity_prefix(activity: &Activity, width: usize) -> Vec<Span<'static>> {
    let narrow = width < NARROW;
    let color = who_color(&activity.who);
    let sender = match (&activity.who, narrow) {
        (crate::state::Who::Agent(role), false) => {
            format!("{} {}", glyph(*role), role_label(*role))
        }
        (crate::state::Who::Agent(role), true) => glyph(*role).to_owned(),
        (who, false) => format!("  {}", who_label(who)),
        (crate::state::Who::System, true) => "◇".to_owned(),
        (crate::state::Who::Me | crate::state::Who::Human(_), true) => "›".to_owned(),
    };
    let (sender_width, tag, tag_width) = if narrow {
        (2, short_tag(activity.tag), 9)
    } else {
        (14, activity.tag, 14)
    };
    vec![
        Span::raw(format!("{} ", activity.at)).fg(DIM),
        Span::raw(pad(&sender, sender_width)).fg(color),
        Span::raw(pad(tag, tag_width))
            .fg(tone_color(activity.tone))
            .bold(),
    ]
}

/// Panes narrower than this get the compact trace prefix.
const NARROW: usize = 90;

/// A tag in at most eight letters, for narrow panes.
fn short_tag(tag: &'static str) -> &'static str {
    match tag {
        "BLOCKED BY OS" => "BLOCKED",
        "TOOL REQUEST" => "TOOL",
        "LEGAL CLOCK" => "CLOCK",
        "INVESTIGATE" => "START",
        "GUARDRAILS" => "GUARD",
        "ADMISSION" => "ADMIT",
        other => other,
    }
}

/// Text color of a trace line.
const fn activity_color(tone: Tone) -> Color {
    match tone {
        Tone::Bad => RED,
        Tone::Quiet => MUTED,
        Tone::Plain | Tone::Good | Tone::Warn => TEXT,
    }
}

/// The selected step in full: the line wrapped under its text column, then its details.
fn expanded_lines(activity: &Activity, width: usize) -> Vec<Line<'static>> {
    let surface = Style::new().bg(RAISED_HI);
    let prefix = activity_prefix(activity, width);
    let indent: usize = prefix.iter().map(Span::width).sum();
    let room = width.saturating_sub(indent).max(8);
    let mut lines = Vec::new();
    let mut prefix = Some(prefix);
    let text_style = surface.fg(activity_color(activity.tone)).bold();
    for chunk in wrap(&activity.text, room) {
        let mut spans = prefix
            .take()
            .unwrap_or_else(|| vec![Span::raw(" ".repeat(indent))]);
        let fill = room.saturating_sub(width_of(&chunk));
        spans.push(Span::styled(chunk, text_style));
        spans.push(spaces(fill, surface));
        lines.push(Line::from(spans).style(surface));
    }
    for chunk in activity.detail.lines().flat_map(|line| wrap(line, room)) {
        let fill = room.saturating_sub(width_of(&chunk));
        lines.push(
            Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(chunk, surface.fg(MUTED)),
                spaces(fill, surface),
            ])
            .style(surface),
        );
    }
    lines
}

// ---------- Approvals, timeline, comms ----------

/// Pending tool requests and proposals, two lines each, with the selected one marked.
fn render_approvals(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    let waiting = state.waiting();
    let focused = view.pane == Pane::Approvals && view.focus == Focus::Keys;
    let heading = match (waiting, area.width >= 60) {
        (0, _) => "APPROVALS".to_owned(),
        (_, true) => format!("APPROVALS · {waiting} waiting · a approve · x deny"),
        (_, false) => format!("APPROVALS · {waiting} waiting"),
    };
    let mut block = panel(title(&heading, focused), focused);
    if waiting > 0 && !focused {
        block = block.border_style(Style::new().fg(AMBER));
    }
    if state.queue.is_empty() {
        frame.render_widget(
            Paragraph::new("Nothing waiting for your signature.")
                .fg(DIM)
                .block(block),
            area,
        );
        return;
    }
    let inner = block.inner(area);
    let fits = (usize::from(inner.height) / 2).max(1);
    let first = view.selected.saturating_sub(fits - 1);
    let width = usize::from(inner.width);
    let lines: Vec<Line<'static>> = state
        .queue
        .iter()
        .enumerate()
        .skip(first)
        .take(fits)
        .flat_map(|(index, item)| queue_lines(item, index == view.selected, width))
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// One queued item: who wants what, then the reason and the subject id, cut to `width`.
fn queue_lines(item: &QueueItem, selected: bool, width: usize) -> [Line<'static>; 2] {
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
    let who = format!("{} ", who_label(&item.from));
    let sent = match item.sent {
        None => String::new(),
        Some(true) => "  approved, confirming…".to_owned(),
        Some(false) => "  denied, confirming…".to_owned(),
    };
    let used = 2 + kind.len() + 1 + width_of(&who) + width_of(&sent);
    let first = Line::from(vec![
        Span::raw(if selected { "▸ " } else { "  " })
            .fg(AMBER)
            .bold(),
        Span::raw(format!("{kind} ")).fg(AMBER).bold(),
        Span::raw(who).fg(who_color(&item.from)).bold(),
        Span::raw(fit(&headline, width.saturating_sub(used)))
            .fg(BRIGHT)
            .bold(),
        Span::raw(sent).fg(if item.sent == Some(false) {
            RED
        } else {
            ACCENT
        }),
    ]);
    let second = Line::from(vec![
        Span::raw("    "),
        Span::raw(fit(
            &format!("{detail} · {}", item.subject_id),
            width.saturating_sub(4),
        ))
        .fg(DIM),
    ]);
    if selected {
        [first.bg(RAISED_HI), second.bg(RAISED_HI)]
    } else {
        [first, second]
    }
}

/// The incident record's timeline.
fn render_timeline(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let block = panel(title("INCIDENT TIMELINE", false), false);
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
        frame.render_widget(Paragraph::new(hint).fg(DIM).block(block), area);
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
                Span::raw(state.time_label(&entry.at)).fg(DIM),
                Span::raw(" "),
                Span::raw(format!("{} ", who_label(&who))).fg(who_color(&who)),
            ],
            text: format!("{}{evidence}", entry.text),
            style: Style::new().fg(TEXT),
            below: false,
        }
    });
    let lines = tail(log, usize::from(inner.width), usize::from(inner.height));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Every chat on the bus: the commander, the Lead and the specialists.
fn render_comms(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let block = panel(title("COMMS · c to write", false), false);
    let said: Vec<&crate::state::Said> = state
        .talk
        .iter()
        .filter_map(|item| match item {
            Talk::Said(said) => Some(said),
            Talk::Marker(_) => None,
        })
        .collect();
    if said.is_empty() {
        frame.render_widget(
            Paragraph::new("No messages. Press c to write to the Lead.")
                .fg(DIM)
                .block(block),
            area,
        );
        return;
    }
    let inner = block.inner(area);
    let log = said.into_iter().map(|line| {
        let to = match &line.to {
            Audience::Role { role } => team::title(*role),
            Audience::Humans | Audience::All => audience_title(&line.to),
        };
        LogEntry {
            prefix: vec![
                Span::raw(format!("{} ", line.at)).fg(DIM),
                Span::raw(who_label(&line.from))
                    .fg(who_color(&line.from))
                    .bold(),
                Span::raw(" → ").fg(DIM),
                Span::raw(to).fg(MUTED),
            ],
            text: crate::state::one_line(&line.text),
            style: Style::new().fg(TEXT),
            below: true,
        }
    });
    let lines = tail(log, usize::from(inner.width), usize::from(inner.height));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// The chat line that replaces the hint bar while typing on this screen.
pub(super) fn render_message_line(frame: &mut Frame<'_>, area: Rect, view: &View) {
    let to = view
        .draft
        .strip_prefix('@')
        .and_then(|rest| team::mention(rest.split(' ').next().unwrap_or_default()))
        .unwrap_or(cleanroom_proto::Role::Lead);
    let prompt = vec![
        Span::styled(" MESSAGE ", Style::new().fg(BRIGHT).bg(RAISED_HI).bold()),
        Span::raw(" → ").fg(DIM),
        Span::raw(format!("{} {}", glyph(to), team::title(to))).fg(tint(to)),
        Span::raw("  "),
    ];
    let help = "   Enter sends · @hunter asks a specialist · Esc cancels";
    let used: usize = prompt.iter().map(Span::width).sum();
    let room = usize::from(area.width).saturating_sub(used + width_of(help));
    let typed = fit(&view.draft, room);
    let cursor_x = area
        .x
        .saturating_add(u16::try_from(used + width_of(&typed)).unwrap_or(u16::MAX));
    let mut spans = prompt;
    spans.push(Span::raw(typed).fg(BRIGHT));
    spans.push(Span::raw(help).fg(DIM));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
    frame.set_cursor_position(Position::new(
        cursor_x.min(area.right().saturating_sub(1)),
        area.y,
    ));
}

/// One entry of a wrapped log pane: fixed prefix columns, then text that wraps under itself
/// (or, with `below`, starts on the next line, indented).
#[derive(Debug)]
struct LogEntry {
    /// Time, sender and tag columns.
    prefix: Vec<Span<'static>>,
    /// The entry's text.
    text: String,
    /// Style of the text.
    style: Style,
    /// Text goes under the prefix instead of beside it, for narrow panes with long prefixes.
    below: bool,
}

impl LogEntry {
    /// The entry wrapped to `width` columns.
    fn lines(self, width: usize) -> Vec<Line<'static>> {
        if self.below {
            let mut lines = vec![Line::from(self.prefix)];
            lines.extend(
                wrap(&self.text, width.saturating_sub(2).max(8))
                    .into_iter()
                    .map(|chunk| {
                        Line::from(vec![Span::raw("  "), Span::styled(chunk, self.style)])
                    }),
            );
            return lines;
        }
        let indent: usize = self.prefix.iter().map(Span::width).sum();
        let mut prefix = Some(self.prefix);
        wrap(&self.text, width.saturating_sub(indent).max(8))
            .into_iter()
            .map(|chunk| {
                let mut spans = prefix
                    .take()
                    .unwrap_or_else(|| vec![Span::raw(" ".repeat(indent))]);
                spans.push(Span::styled(chunk, self.style));
                Line::from(spans)
            })
            .collect()
    }
}

/// The newest entries that fit in `rows` lines of `width` columns, oldest first.
///
/// Each entry wraps, so the prefix columns stay scannable and long text is not cut off. An
/// older entry that would only partly fit is left out; the newest entry, if taller than the
/// pane, shows its start and an ellipsis. Blank lines keep the newest entry at the bottom.
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
        let mut wrapped = entry.lines(width);
        if wrapped.len() > room {
            if !newest_first.is_empty() {
                newest_first.resize_with(rows, Line::default);
                break;
            }
            wrapped.truncate(room);
            if let Some(last) = wrapped.last_mut() {
                last.spans.push(Span::raw(" …").fg(DIM));
            }
        }
        newest_first.extend(wrapped.into_iter().rev());
    }
    newest_first.reverse();
    newest_first
}
