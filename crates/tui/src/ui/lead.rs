//! The Lead tab, and the conversation the Controlroom shares.
//!
//! The conversation with the Lead fills the left; the team and the approvals waiting sit on the
//! right. After every OS denial the kernel banner is pinned over the conversation for 8 seconds.

use cleanroom_proto::{Audience, Role};
use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Padding, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use super::{
    Focus, View, fit, heading, on, pad, panel, role_label, role_name, short_model, spaces, spinner,
    tail_fit, width_of, wrap,
};
use crate::denials::{Denial, Kind};
use crate::state::{Ask, Marker, QueueItem, Said, State, Talk, Tone, Who};
use crate::team::{self, SPECIALISTS, Status};
use crate::theme::{
    ACCENT, AMBER, BRIGHT, DIM, INK, LINE, MUTED, RAISED, RAISED_HI, RED, RED_BG, TEXT, blend,
    glyph, tint,
};

/// How long a new message takes to fade in.
const FADE_IN_MS: i64 = 600;

/// Widest a Lead or specialist message runs before wrapping, for a comfortable measure.
const MEASURE: usize = 86;
/// Longest message shown in full; the Controlroom comms pane keeps the whole text.
const MESSAGE_LINES: usize = 16;
/// Columns before a card's name: the trunk and its branch.
const GUTTER: usize = 6;

/// The Lead tab: the conversation, with the team and the approvals waiting beside it.
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let side = match area.width {
        150.. => 52,
        130.. => 46,
        110.. => 42,
        _ => 0,
    };
    if side == 0 {
        let [_, talk, _] = Layout::horizontal([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        render_conversation(frame, talk, state, view, now);
        return;
    }
    let [_, talk, _, column, _] = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(2),
        Constraint::Length(side),
        Constraint::Length(2),
    ])
    .areas(area);
    render_conversation(frame, talk, state, view, now);
    render_column(frame, column, state, view, now);
}

// ---------- Conversation ----------

/// The conversation panel: banner, messages, the latest notice and the message line.
pub(super) fn render_conversation(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let focused = view.focus == Focus::Input;
    let title = Line::from(vec![
        Span::raw(" ◆ ").fg(ACCENT),
        Span::raw("LEAD").fg(BRIGHT).bold(),
        Span::raw(" · conversation ").fg(MUTED),
    ]);
    let mut block = panel(title, focused).padding(Padding::horizontal(1));
    if view.scroll > 0 {
        block = block.title(
            Line::from(" scrolled back · End returns to the newest ")
                .fg(DIM)
                .right_aligned(),
        );
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let banner = state.denials.banner(now);
    let banner_height = match banner {
        Some(_) if inner.height >= 16 => 4,
        Some(_) => 2,
        None => 0,
    };
    let [banner_area, _, feed, notice, rule, input] = Layout::vertical([
        Constraint::Length(banner_height),
        Constraint::Length(u16::from(banner.is_some())),
        Constraint::Fill(1),
        Constraint::Length(u16::from(state.notice.is_some())),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    if let Some(denial) = banner {
        render_banner(frame, banner_area, denial);
    }
    render_feed(frame, feed, state, view, now);
    if let Some(note) = &state.notice {
        let room = usize::from(notice.width).saturating_sub(2);
        let line = Line::from(vec![
            Span::raw("↳ ").fg(DIM),
            Span::raw(fit(&note.text, room)).fg(super::tone_color(note.tone)),
        ]);
        frame.render_widget(Paragraph::new(line), notice);
    }
    let rule_line = "─".repeat(usize::from(rule.width));
    frame.render_widget(Paragraph::new(rule_line).fg(LINE), rule);
    render_input(frame, input, view, focused);
}

/// The kernel banner: what was blocked, for whom, why, and the receipt that proves it.
fn render_banner(frame: &mut Frame<'_>, area: Rect, denial: &Denial) {
    frame.render_widget(Block::new().style(Style::new().bg(RED_BG).fg(BRIGHT)), area);
    let width = usize::from(area.width);
    let (headline, reason) = match denial.kind {
        Kind::Exec => (
            "KERNEL BLOCKED",
            denial.reason.replace("read_only", "read-only"),
        ),
        Kind::Record => ("OS KEPT THE RECORD", denial.reason.clone()),
    };
    let who = denial.role.map_or_else(
        || denial.who.to_uppercase(),
        |role| format!("{} {}", glyph(role), role_label(role)),
    );
    let lead = format!("  ⛔ {headline}    {who}    ");
    let command = fit(&denial.command, width.saturating_sub(width_of(&lead) + 1));
    let first = Line::from(vec![
        Span::raw("  ⛔ ").bold(),
        Span::raw(headline).bold(),
        Span::raw("    "),
        Span::raw(who).bold(),
        Span::raw("    "),
        Span::raw(command).bold(),
    ]);
    let mut facts = vec![reason];
    if let Some(seq) = denial.receipt {
        facts.push(format!("signed receipt #{seq}"));
    }
    if let Some(step) = denial.step {
        facts.push(format!("step #{step}"));
    }
    let second = Line::from(format!(
        "     {}",
        fit(&facts.join(" · "), width.saturating_sub(6))
    ));
    let top = u16::from(area.height >= 4);
    let [_, first_area, second_area, _] = Layout::vertical([
        Constraint::Length(top),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    frame.render_widget(Paragraph::new(first), first_area);
    frame.render_widget(Paragraph::new(second), second_area);
}

/// The messages and markers, newest at the bottom, scrolled back by `view.scroll` lines, with a
/// scrollbar when they overflow. With motion on, a message that just arrived fades in.
fn render_feed(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let rows = usize::from(area.height);
    if rows == 0 {
        return;
    }
    let lines = feed_lines(state, usize::from(area.width));
    if lines.is_empty() {
        frame.render_widget(Paragraph::new(empty_feed(rows)), area);
        return;
    }
    let limit = lines.len().saturating_sub(rows);
    view.scroll_limit.set(limit);
    let back = view.scroll.min(limit);
    let end = lines.len() - back;
    let start = end.saturating_sub(rows);
    let mut shown: Vec<Line<'static>> = vec![Line::default(); rows - (end - start)];
    shown.extend(lines.into_iter().skip(start).take(end - start));
    frame.render_widget(Paragraph::new(shown), area);
    if limit > 0 {
        let mut position = ScrollbarState::new(limit).position(limit - back);
        let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .track_style(Style::new().fg(LINE))
            .thumb_symbol("┃")
            .thumb_style(Style::new().fg(ACCENT));
        frame.render_stateful_widget(bar, area, &mut position);
    }
    if view.motion && back == 0 {
        fade_in_newest(frame, area, state, now);
    }
}

/// Fade the newest message in over its first moments: its rows start near the background.
fn fade_in_newest(frame: &mut Frame<'_>, area: Rect, state: &State, now: Timestamp) {
    let Some(Talk::Said(said)) = state.talk.back() else {
        return;
    };
    let age = now.duration_since(said.arrived).as_millis();
    if !(0..i128::from(FADE_IN_MS)).contains(&age) {
        return;
    }
    let mut own = Vec::new();
    message_lines(said, usize::from(area.width), &mut own);
    let height = u16::try_from(own.len())
        .unwrap_or(u16::MAX)
        .min(area.height);
    let left = i128::from(FADE_IN_MS) - age;
    let amount = u16::try_from(left * 256 / i128::from(FADE_IN_MS)).unwrap_or(0);
    let buffer = frame.buffer_mut();
    for y in area.bottom().saturating_sub(height)..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buffer.cell_mut((x, y)) {
                let faded = blend(cell.fg, INK, amount);
                cell.set_fg(faded);
            }
        }
    }
}

/// What the conversation says before anything happened.
fn empty_feed(rows: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::default(); rows.saturating_sub(5) / 2];
    lines.extend([
        Line::from(Span::raw("◆").fg(ACCENT)).centered(),
        Line::default(),
        Line::from("The Lead is standing by.").fg(TEXT).centered(),
        Line::from("Ask what happened, what to do first, or to check on a specialist.")
            .fg(MUTED)
            .centered(),
        Line::from("Nothing has happened yet: Esc, then d detonates a scenario.")
            .fg(DIM)
            .centered(),
    ]);
    lines
}

/// How an entry sits in the conversation, for spacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A full message from the commander, the Lead or a specialist answering a human.
    Message,
    /// A compact delegation, reply or report between agents.
    Card,
    /// A key system event.
    Marker,
}

/// Every conversation line at `width`, oldest first.
fn feed_lines(state: &State, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut previous: Option<Class> = None;
    for item in &state.talk {
        let class = match item {
            Talk::Marker(_) => Class::Marker,
            Talk::Said(said) => said_class(said),
        };
        if previous.is_some_and(|previous| class == Class::Message || previous != class) {
            lines.push(Line::default());
        }
        previous = Some(class);
        match item {
            Talk::Marker(marker) => lines.push(marker_line(marker, width)),
            Talk::Said(said) => match said_class(said) {
                Class::Message => message_lines(said, width, &mut lines),
                Class::Card | Class::Marker => card_lines(said, width, &mut lines),
            },
        }
    }
    lines
}

/// Whether a chat message is a full message or a compact card.
const fn said_class(said: &Said) -> Class {
    match (&said.from, &said.to) {
        (Who::Me | Who::Human(_) | Who::System, _)
        | (Who::Agent(_), Audience::Humans)
        | (Who::Agent(Role::Lead), Audience::All) => Class::Message,
        (Who::Agent(_), Audience::Role { .. } | Audience::All) => Class::Card,
    }
}

/// `• 04:38:24  incident INC-7 declared: Ransomware on acme-fs`.
fn marker_line(marker: &Marker, width: usize) -> Line<'static> {
    let color = match marker.tone {
        Tone::Quiet | Tone::Plain => DIM,
        Tone::Good => ACCENT,
        Tone::Warn => AMBER,
        Tone::Bad => RED,
    };
    let lead = format!("  • {}  ", marker.at);
    let text = fit(&marker.text, width.saturating_sub(width_of(&lead)));
    Line::from(vec![
        Span::raw("  • ").fg(color),
        Span::raw(format!("{}  ", marker.at)).fg(DIM),
        Span::raw(text).fg(if marker.tone == Tone::Plain {
            MUTED
        } else {
            color
        }),
    ])
}

/// A full message: the commander's right-aligned, everyone else's left-aligned.
fn message_lines(said: &Said, width: usize, lines: &mut Vec<Line<'static>>) {
    match &said.from {
        Who::Me | Who::Human(_) => commander_lines(said, width, lines),
        Who::Agent(role) => agent_lines(*role, said, width, lines),
        Who::System => agent_lines(Role::Lead, said, width, lines),
    }
}

/// The commander's message: a right-aligned bubble under `you · 04:39:02`.
fn commander_lines(said: &Said, width: usize, lines: &mut Vec<Line<'static>>) {
    let mut header = vec![
        Span::raw(match &said.from {
            Who::Human(short) => format!("human {short}"),
            Who::Me | Who::Agent(_) | Who::System => "you".to_owned(),
        })
        .fg(BRIGHT)
        .bold(),
    ];
    if let Audience::Role { role } = &said.to
        && *role != Role::Lead
    {
        header.extend([Span::raw(" → ").fg(DIM), role_name(*role)]);
    }
    header.extend([Span::raw(format!("  {}", said.at)).fg(DIM), Span::raw(" ")]);
    lines.push(Line::from(header).right_aligned());
    let measure = (width * 3 / 5).max(24).min(width.saturating_sub(4));
    let wrapped = wrap(&clean(&said.text), measure.saturating_sub(2));
    let bubble = wrapped.iter().map(|line| width_of(line)).max().unwrap_or(0) + 2;
    let bubble_style = Style::new().bg(RAISED_HI).fg(BRIGHT);
    for line in wrapped.into_iter().take(MESSAGE_LINES) {
        let fill = bubble.saturating_sub(width_of(&line) + 1);
        lines.push(
            Line::from(vec![
                Span::styled(format!(" {line}"), bubble_style),
                spaces(fill, bubble_style),
                Span::raw(" "),
            ])
            .right_aligned(),
        );
    }
}

/// A message from the Lead (or a specialist answering a human): `◆ LEAD  04:39:20`, then the
/// text, left-aligned at a comfortable measure.
fn agent_lines(role: Role, said: &Said, width: usize, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::raw(format!("{} ", glyph(role))).fg(tint(role)),
        Span::raw(role_label(role)).fg(BRIGHT).bold(),
        Span::raw(format!("  {}", said.at)).fg(DIM),
    ]));
    let measure = width.saturating_sub(2).min(MEASURE);
    let wrapped = wrap(&clean(&said.text), measure);
    let total = wrapped.len();
    for (index, line) in wrapped.into_iter().take(MESSAGE_LINES).enumerate() {
        let text = if index + 1 == MESSAGE_LINES && total > MESSAGE_LINES {
            format!("{line} …")
        } else {
            line
        };
        lines.push(Line::from(vec![Span::raw("  "), Span::raw(text).fg(TEXT)]));
    }
}

/// A compact card between agents: `│ ◆ Lead → ▲ Hunter  What did you find?`, two lines at most.
fn card_lines(said: &Said, width: usize, lines: &mut Vec<Line<'static>>) {
    let Who::Agent(from) = said.from else {
        return;
    };
    let mut header = vec![
        Span::raw("    │ ").fg(LINE),
        role_name(from),
        Span::raw(" → ").fg(DIM),
    ];
    match &said.to {
        Audience::Role { role } => header.push(role_name(*role)),
        Audience::All => header.push(Span::raw("team").fg(MUTED)),
        Audience::Humans => header.push(Span::raw("you").fg(BRIGHT)),
    }
    header.push(Span::raw("  "));
    let used: usize = header.iter().map(Span::width).sum();
    let text = crate::state::one_line(&said.text);
    let first_room = width.saturating_sub(used);
    let wrapped = wrap(&text, first_room.max(8));
    let first = wrapped.first().cloned().unwrap_or_default();
    let rest: String = wrapped.get(1..).unwrap_or_default().join(" ");
    let second_room = width.saturating_sub(GUTTER);
    header.push(Span::raw(first).fg(MUTED));
    lines.push(Line::from(header));
    if !rest.is_empty() {
        lines.push(Line::from(vec![
            Span::raw("    │ ").fg(LINE),
            Span::raw(fit(&rest, second_room)).fg(MUTED),
        ]));
    }
}

/// Message text for the screen: markdown emphasis and headings dropped, blank runs collapsed.
fn clean(text: &str) -> String {
    let mut out = Vec::new();
    let mut blank = false;
    for line in text.lines() {
        let line = line
            .trim_end()
            .trim_start_matches('#')
            .trim_start()
            .replace("**", "")
            .replace("__", "")
            .replace('`', "");
        if line.chars().all(|ch| matches!(ch, '|' | '-' | ':' | ' ')) && !line.is_empty() {
            continue;
        }
        if line.is_empty() {
            if !blank && !out.is_empty() {
                out.push(String::new());
            }
            blank = true;
        } else {
            out.push(line);
            blank = false;
        }
    }
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.join("\n")
}

/// The message line: `› ` and the draft, or a hint of what to type.
fn render_input(frame: &mut Frame<'_>, area: Rect, view: &View, focused: bool) {
    let width = usize::from(area.width);
    let prompt = Span::raw("› ")
        .fg(if focused { ACCENT } else { DIM })
        .bold();
    let send = if focused {
        "Enter ↵ "
    } else {
        "Enter to type "
    };
    let room = width.saturating_sub(2 + width_of(send) + 1);
    let mut spans = vec![prompt];
    if view.draft.is_empty() {
        let placeholder = match (focused, room >= 84) {
            (true, true) => {
                "Ask the Lead anything · @hunter, @forensics, @scribe or @containment asks a specialist"
            }
            (true, false) => "Ask the Lead · @hunter asks a specialist",
            (false, _) => "Press Enter to talk to the Lead",
        };
        spans.push(Span::raw(fit(placeholder, room)).fg(DIM));
    } else {
        let shown = tail_fit(&view.draft, room);
        spans.extend(draft_spans(&shown, focused));
        if focused {
            let x = area
                .x
                .saturating_add(2)
                .saturating_add(u16::try_from(width_of(&shown)).unwrap_or(u16::MAX));
            frame.set_cursor_position(Position::new(x.min(area.right().saturating_sub(1)), area.y));
        }
    }
    let used: usize = spans.iter().map(Span::width).sum();
    spans.push(Span::raw(
        " ".repeat(width.saturating_sub(used + width_of(send))),
    ));
    spans.push(Span::raw(send).fg(DIM));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
    if focused && view.draft.is_empty() {
        frame.set_cursor_position(Position::new(area.x.saturating_add(2), area.y));
    }
}

/// The draft, with a leading `@name` in the addressed role's tint (red when nobody has it).
fn draft_spans(shown: &str, focused: bool) -> Vec<Span<'static>> {
    let text_color = if focused { BRIGHT } else { MUTED };
    let Some(rest) = shown.strip_prefix('@') else {
        return vec![Span::raw(shown.to_owned()).fg(text_color)];
    };
    let (name, tail) = rest
        .split_once(' ')
        .map_or((rest, ""), |(name, tail)| (name, tail));
    let color = team::mention(name).map_or(RED, tint);
    let mut spans = vec![Span::raw(format!("@{name}")).fg(color).bold()];
    if !tail.is_empty() || rest.contains(' ') {
        spans.push(Span::raw(format!(" {tail}")).fg(text_color));
    }
    spans
}

// ---------- Right column ----------

/// The team on top, the approvals waiting below.
fn render_column(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let team_height: u16 = 2 + 2 + 3 * 4;
    let [team_area, _, approvals] = Layout::vertical([
        Constraint::Length(team_height),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    render_team(frame, team_area, state, now);
    let mut lines = Vec::new();
    approval_lines(state, view, usize::from(approvals.width), &mut lines);
    frame.render_widget(Paragraph::new(lines), approvals);
}

/// The Lead's card, and the four specialists hanging off it. A link lights while the Lead waits
/// on that specialist.
pub(super) fn render_team(frame: &mut Frame<'_>, area: Rect, state: &State, now: Timestamp) {
    let width = usize::from(area.width);
    let mut lines = vec![heading("TEAM"), Line::default()];
    lines.extend(agent_card(Role::Lead, state, width, now));
    let lit = SPECIALISTS.map(|role| state.team.link(role, now));
    let lowest = lit.iter().rposition(|lit| *lit);
    let wire = |on: bool| Style::new().fg(if on { ACCENT } else { LINE });
    for (index, role) in SPECIALISTS.into_iter().enumerate() {
        let last = index + 1 == SPECIALISTS.len();
        let through = lowest.is_some_and(|lowest| index <= lowest);
        let below = lowest.is_some_and(|lowest| index < lowest);
        let branch = lit.get(index).copied().unwrap_or(false);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("│", wire(through)),
        ]));
        let [first, second] = agent_card(role, state, width.saturating_sub(GUTTER), now);
        let mut top = vec![
            Span::raw("  "),
            Span::styled(if last { "└" } else { "├" }, wire(through)),
            Span::styled("── ", wire(branch)),
        ];
        top.extend(first.spans);
        lines.push(Line::from(top));
        let mut bottom = vec![
            Span::raw("  "),
            Span::styled(if last { " " } else { "│" }, wire(below)),
            Span::raw("   "),
        ];
        bottom.extend(second.spans);
        lines.push(Line::from(bottom));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// A two-line card, `width` columns wide: glyph, name, model and status, then the last action.
pub(super) fn agent_card(
    role: Role,
    state: &State,
    width: usize,
    now: Timestamp,
) -> [Line<'static>; 2] {
    let card = Style::new().bg(RAISED);
    let desk = state.team.desk(role);
    let status = state.team.status(role, state.waiting_on(role), now);
    let status_spans = status_spans(&status, now);
    let status_width: usize = status_spans.iter().map(Span::width).sum();
    let model = desk
        .model
        .as_deref()
        .map(short_model)
        .map(|model| match desk.route {
            Some(cleanroom_proto::ModelRoute::Local) => format!("{model} · local"),
            Some(cleanroom_proto::ModelRoute::Hosted) | None => model,
        });
    let name = pad(role_label(role), 12);
    let mut top = vec![
        Span::styled(format!(" {} ", glyph(role)), card.fg(tint(role))),
        Span::styled(name, card.fg(BRIGHT).bold()),
    ];
    let room = width.saturating_sub(16 + status_width + 1);
    let model = model.as_deref().filter(|_| room >= 10).unwrap_or("");
    let model_text = fit(model, room.saturating_sub(1));
    top.push(Span::styled(model_text.clone(), card.fg(DIM)));
    let fill = width.saturating_sub(16 + width_of(&model_text) + status_width + 1);
    top.push(spaces(fill, card));
    top.extend(status_spans.into_iter().map(|span| on(card, span)));
    top.push(spaces(1, card));
    let blocked = status == Status::Blocked;
    let last = desk.last.as_deref().unwrap_or(match role {
        Role::Lead => "waiting for your question",
        Role::Hunter | Role::Forensics | Role::Scribe | Role::Containment => "no activity yet",
    });
    let last = fit(last, width.saturating_sub(5));
    let last_color = if blocked {
        RED
    } else if desk.last.is_some() {
        MUTED
    } else {
        DIM
    };
    let used = 4 + width_of(&last);
    let bottom = vec![
        Span::styled("    ", card),
        Span::styled(last, card.fg(last_color)),
        spaces(width.saturating_sub(used), card),
    ];
    [Line::from(top), Line::from(bottom)]
}

/// The status at the right of a card.
pub(super) fn status_spans(status: &Status, now: Timestamp) -> Vec<Span<'static>> {
    match status {
        Status::Idle => vec![Span::raw("idle").fg(DIM)],
        Status::Thinking => vec![
            Span::raw(spinner(now)).fg(ACCENT),
            Span::raw(" thinking").fg(MUTED),
        ],
        Status::Asking(roles) => {
            let names: Vec<&str> = roles.iter().map(|role| team::title(*role)).collect();
            vec![
                Span::raw(spinner(now)).fg(ACCENT),
                Span::raw(format!(" asking {}", names.join(", "))).fg(ACCENT),
            ]
        }
        Status::Running(tool) => vec![
            Span::raw("▸ ").fg(ACCENT),
            Span::raw(fit(tool, 18)).fg(TEXT).bold(),
        ],
        Status::Blocked => vec![Span::styled(
            " BLOCKED BY OS ",
            Style::new().fg(BRIGHT).bg(RED_BG).bold(),
        )],
        Status::Refused => vec![Span::raw("✓ refused").fg(ACCENT).bold()],
        Status::Waiting => vec![Span::raw("waiting on you").fg(AMBER).bold()],
    }
}

/// What waits for the commander's signature, with the keys that decide it.
pub(super) fn approval_lines(
    state: &State,
    view: &View,
    width: usize,
    lines: &mut Vec<Line<'static>>,
) {
    let waiting = state.waiting();
    let mut header = vec![Span::raw("APPROVALS").fg(MUTED).bold()];
    if waiting > 0 {
        header.extend([
            Span::raw(format!("   {waiting} waiting")).fg(AMBER).bold(),
            Span::raw("   a approve · x deny").fg(DIM),
        ]);
    }
    lines.push(Line::from(header));
    if state.queue.is_empty() {
        lines.push(Line::from("  nothing waiting for your signature").fg(DIM));
        return;
    }
    let first = view.selected.saturating_sub(2);
    for (index, item) in state.queue.iter().enumerate().skip(first).take(3) {
        lines.push(queue_line(item, index == view.selected, width));
    }
}

/// `▸ ▣ Containment  isolate host acme-fs from the network`.
fn queue_line(item: &QueueItem, selected: bool, width: usize) -> Line<'static> {
    let base = if selected {
        Style::new().bg(RAISED_HI)
    } else {
        Style::new()
    };
    let what = match &item.ask {
        Ask::Tool { tool, .. } => format!("wants {tool}"),
        Ask::Proposal { action, .. } => action.clone(),
    };
    let who = match &item.from {
        Who::Agent(role) => role_name(*role),
        Who::System | Who::Me | Who::Human(_) => Span::raw(crate::state::who_title(&item.from)),
    };
    let status = match item.sent {
        None => String::new(),
        Some(true) => "  approved, confirming…".to_owned(),
        Some(false) => "  denied, confirming…".to_owned(),
    };
    let used = 2 + who.width() + 2 + width_of(&status);
    let what = fit(&what, width.saturating_sub(used + 1));
    let fill = width.saturating_sub(used + width_of(&what));
    Line::from(vec![
        Span::styled(if selected { "▸ " } else { "  " }, base.fg(AMBER).bold()),
        on(base, who),
        Span::styled("  ", base),
        Span::styled(what, base.fg(TEXT)),
        Span::styled(status, base.fg(MUTED)),
        spaces(fill, base),
    ])
}
