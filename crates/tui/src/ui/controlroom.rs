//! The Controlroom: the complete operator screen.
//!
//! Every OS denial is pinned in a strip at the top so it never scrolls away. Below it sit the
//! legal clocks, the scope table, the agent trace (one line per step; the selected step expands)
//! over the conversation with the Lead, and a side column with the team, the approvals waiting,
//! the defense layers and the incident timeline.

use cleanroom_proto::{DataClass, Role, ScopeRecord};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table};

use super::lead::{agent_card, approval_lines, render_conversation};
use super::{
    Focus, Pane, View, clock_text, fit, flag_look, grouped, pad, panel, role_label, spaces, title,
    tone_color, who_color, who_label, width_of, wrap,
};
use crate::clocks::{self, Clock};
use crate::denials::{Denial, Kind};
use crate::state::{Activity, State, Tone};
use crate::team::SPECIALISTS;
use crate::theme::{
    ACCENT, AMBER, BRIGHT, DIM, INK, LINE, MUTED, RAISED, RAISED_HI, RED, TEXT, glyph, tint,
};

/// Draw the screen into `area`, everything between the header and the key bar.
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
    let most = if inner.height < 32 { 2 } else { 3 };
    let strip_rows = state.denials.len().clamp(1, most);
    let strip_height = u16::try_from(strip_rows).unwrap_or(1).saturating_add(2);
    let scope_rows = u16::try_from(state.scope.len()).unwrap_or(u16::MAX);
    let [strip, clock_line, scope, lower] = Layout::vertical([
        Constraint::Length(strip_height),
        Constraint::Length(1),
        Constraint::Length(scope_rows.saturating_add(3).clamp(4, 9)),
        Constraint::Fill(1),
    ])
    .areas(inner);
    render_strip(frame, strip, state);
    let all = clocks::clocks(&state.triggers(), &state.scope);
    render_clock_line(frame, clock_line, &all, now, &state.display_tz);
    render_scope(frame, scope, state);
    let side = match lower.width {
        150.. => 50,
        110.. => 42,
        _ => 0,
    };
    let [work, _, column] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(u16::from(side > 0)),
        Constraint::Length(side),
    ])
    .areas(lower);
    let [trace, talk] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Fill(1)]).areas(work);
    render_trace(frame, trace, state, view);
    render_conversation(frame, talk, state, view, now);
    if side > 0 {
        render_side(frame, column, state, view, now);
    }
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
            format!(" · {earlier} earlier on Defense F5")
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

// ---------- Clocks and scope ----------

/// All five clocks on one line: name, countdown and day.
fn render_clock_line(
    frame: &mut Frame<'_>,
    area: Rect,
    all: &[Clock; 5],
    now: Timestamp,
    tz: &TimeZone,
) {
    let mut spans = vec![Span::raw(" ")];
    for clock in all {
        let (main, _, color) = clock_text(clock, now, tz);
        if spans.len() > 1 {
            spans.push(Span::raw("  │  ").fg(LINE));
        }
        spans.push(Span::raw(format!("{} ", clock.regime.short_label())).fg(MUTED));
        spans.push(Span::styled(main, Style::new().fg(color).bold()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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
                "SCOPE · {} assets · {} records · {} Texans",
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
    let rows = state.scope.iter().enumerate().map(|(index, asset)| {
        let row = scope_row(asset);
        if index % 2 == 0 {
            row.style(Style::new().bg(RAISED))
        } else {
            row
        }
    });
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(Style::new().fg(INK).bg(ACCENT).bold()))
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
pub(super) const fn class_label(class: DataClass) -> &'static str {
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
        None => "AGENT TRACE · live · → then ↑ to pick a step",
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
    let after = total.saturating_sub(selected + 1).min(budget / 2);
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

/// Panes narrower than this get the compact trace prefix.
const NARROW: usize = 90;

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

// ---------- Side column ----------

/// The team, the approvals waiting, the defense layers and the newest timeline entries.
fn render_side(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let width = usize::from(area.width);
    let heading = |text: &str, color: Color| {
        Line::from(vec![
            Span::raw("✦ ").fg(color),
            Span::raw(text.to_owned()).fg(color).bold(),
        ])
    };
    let mut lines = vec![heading("TEAM", ACCENT)];
    for role in std::iter::once(Role::Lead).chain(SPECIALISTS) {
        lines.extend(agent_card(role, state, width, now));
    }
    lines.push(Line::default());
    let approvals_focused = view.pane == Pane::Approvals && view.focus == Focus::Keys;
    let mut approvals = Vec::new();
    approval_lines(state, view, width, &mut approvals);
    if let Some(first) = approvals.first_mut() {
        let color = if approvals_focused { ACCENT } else { MUTED };
        *first = Line::from(
            std::iter::once(Span::raw("✦ ").fg(color))
                .chain(first.spans.drain(..))
                .collect::<Vec<_>>(),
        );
    }
    lines.extend(approvals);
    lines.push(Line::default());
    lines.push(heading("DEFENSE LAYERS", ACCENT));
    let counters = state.counters;
    let count =
        |value: Option<u32>| value.map_or_else(|| "–".to_owned(), |value| value.to_string());
    for (label, value, color) in [
        (
            "safety flagged",
            count(counters.map(|counters| counters.safety_flags)),
            AMBER,
        ),
        (
            "model refused",
            count(counters.map(|counters| counters.blocked_by_model)),
            ACCENT,
        ),
        ("kernel blocked", state.blocks().to_string(), RED),
    ] {
        lines.push(Line::from(vec![
            Span::raw(format!("  {label:<18}")).fg(MUTED),
            Span::raw(format!("{value:>4}")).fg(color).bold(),
        ]));
    }
    let room = usize::from(area.height).saturating_sub(lines.len() + 2);
    if room > 0 {
        lines.push(Line::default());
        lines.push(heading("TIMELINE", ACCENT));
        lines.extend(timeline_lines(state, width, room));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The newest `rows` timeline entries, one line each.
fn timeline_lines(state: &State, width: usize, rows: usize) -> Vec<Line<'static>> {
    let entries = state
        .incident
        .as_ref()
        .map(|incident| incident.timeline.as_slice())
        .unwrap_or_default();
    if entries.is_empty() {
        return vec![Line::from("  Scribe has not written the timeline yet.").fg(DIM)];
    }
    entries
        .iter()
        .rev()
        .take(rows)
        .rev()
        .map(|entry| {
            let at = format!("  {} ", state.time_label(&entry.at));
            let room = width.saturating_sub(width_of(&at));
            Line::from(vec![
                Span::raw(at).fg(DIM),
                Span::raw(fit(&entry.text, room)).fg(TEXT),
            ])
        })
        .collect()
}
