//! The Cleanroom tabs that read the incident: Overview, Scope, Record, Defense and Team.
//!
//! Every tab is a set of rounded panels with the title inset in the border. One panel has focus
//! (`[`/`]` or ←/→ move it): its border turns the bright accent and the key bar shows its keys.
//! Tables get a full-width accent header bar and zebra rows, counts become segmented bars, the
//! Overview charts tool calls, OS denials and safety flags over time, and an empty panel is
//! hatched with what will fill it. Everything comes from the bus state.

use cleanroom_proto::{Role, ScopeRecord, Tri};
use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table};
use tui_big_text::{BigText, PixelSize};

use super::controlroom::class_label;
use super::lead::status_spans;
use super::{
    ChartView, View, clock_text, due_label, fit, flag_look, grouped, pad, role_label,
    running_clocks, severity_word, short_model, urgency_color, wrap,
};
use crate::clocks::{self, ClockState, Regime};
use crate::next::{self, NextAction};
use crate::state::{
    Activity, Admission, Ask, LogStatus, State, Who, compromised, status_word, yes_flags,
};
use crate::team::{self, SPECIALISTS, Status};
use crate::theme::{
    ACCENT, ACCENT_BG, AMBER, BRIGHT, DIM, INK, LINE, MUTED, OK, RAISED, RED, TEXT, glyph, tint,
};

/// Key and action pairs for the key bar.
pub(super) type Keys = &'static [(&'static str, &'static str)];

/// What a panel holds.
enum Body {
    /// Lines of text.
    Lines(Vec<Line<'static>>),
    /// A zebra table: header, rows, column widths.
    Table(Vec<&'static str>, Vec<Row<'static>>, Vec<Constraint>),
    /// The activity chart with its sub-tabs.
    Activity,
    /// The welcome panel.
    Welcome,
    /// The kernel-blocks count in big type.
    Hero,
    /// Nothing yet: hatched, with what will fill it.
    Hatched(&'static str),
}

/// One panel: title, body, rows it wants (`None` to take what is left) and its keys.
struct Panel {
    /// Title in the border.
    title: String,
    /// Content.
    body: Body,
    /// Content rows, or `None` to fill.
    rows: Option<u16>,
    /// Keys the key bar shows while this panel has focus.
    keys: Keys,
}

impl Panel {
    /// A panel of text lines, as tall as its lines.
    fn lines(title: &str, lines: Vec<Line<'static>>, keys: Keys) -> Self {
        let rows = u16::try_from(lines.len()).unwrap_or(u16::MAX);
        Self {
            title: title.to_owned(),
            body: Body::Lines(lines),
            rows: Some(rows),
            keys,
        }
    }

    /// A panel that takes the rest of its column.
    fn fill(title: &str, body: Body, keys: Keys) -> Self {
        Self {
            title: title.to_owned(),
            body,
            rows: None,
            keys,
        }
    }
}

/// Where the panels of a tab go.
struct Page {
    /// Columns of panels, left to right.
    columns: Vec<Vec<Panel>>,
}

impl Page {
    /// Every panel's keys, in focus order (columns left to right, panels top to bottom).
    fn keys(&self) -> Vec<Keys> {
        self.columns
            .iter()
            .flat_map(|column| column.iter().map(|panel| panel.keys))
            .collect()
    }
}

/// The panels of `view.tab` for `state`.
fn page(state: &State, view: &View, now: Timestamp) -> Page {
    match view.tab {
        super::Tab::Overview => overview_page(state, view, now),
        super::Tab::Scope => scope_page(state),
        super::Tab::Record => record_page(state, now),
        super::Tab::Defense => defense_page(state),
        super::Tab::Team
        | super::Tab::Lead
        | super::Tab::Memory
        | super::Tab::System
        | super::Tab::Controlroom => team_page(state, now),
    }
}

/// How many panels `view.tab` has, so focus can wrap.
pub(super) fn panel_count(state: &State, view: &View, now: Timestamp) -> usize {
    page(state, view, now).keys().len()
}

/// The keys of the focused panel, for the key bar.
pub(super) fn focused_keys(state: &State, view: &View, now: Timestamp) -> Keys {
    let keys = page(state, view, now).keys();
    let count = keys.len().max(1);
    keys.get(view.panel % count).copied().unwrap_or(&[])
}

/// Draw `view.tab` into `area`.
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let page = page(state, view, now);
    let count = page.keys().len().max(1);
    let focused = view.panel % count;
    let area = area.inner(Margin::new(1, 1));
    let widths: Vec<Constraint> = page.columns.iter().map(|_| Constraint::Fill(1)).collect();
    let cells = Layout::horizontal(widths).spacing(2).split(area);
    let mut index = 0;
    for (column, cell) in page.columns.into_iter().zip(cells.iter()) {
        let heights: Vec<Constraint> = column
            .iter()
            .map(|panel| {
                panel.rows.map_or(Constraint::Fill(1), |rows| {
                    Constraint::Length(rows.saturating_add(2))
                })
            })
            .collect();
        let slots = Layout::vertical(heights).spacing(1).split(*cell);
        for (panel, slot) in column.into_iter().zip(slots.iter()) {
            draw_panel(frame, *slot, panel, index == focused, (state, view, now));
            index += 1;
        }
    }
}

/// One panel: the rounded border with its inset title, then its body.
fn draw_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    panel: Panel,
    focused: bool,
    (state, view, now): (&State, &View, Timestamp),
) {
    let block = view.palette().panel(&panel.title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    match panel.body {
        Body::Lines(lines) => frame.render_widget(Paragraph::new(lines), inner),
        Body::Table(header, rows, widths) => {
            frame.render_widget(zebra(header, rows, widths), inner);
        }
        Body::Activity => activity_chart(frame, inner, state, view, now),
        Body::Welcome => welcome(frame, inner),
        Body::Hero => hero(frame, inner, state),
        Body::Hatched(text) => hatched(frame, inner, text),
    }
}

/// A table with a full-width accent header bar and zebra rows.
fn zebra(
    header: Vec<&'static str>,
    rows: Vec<Row<'static>>,
    widths: Vec<Constraint>,
) -> Table<'static> {
    let rows = rows.into_iter().enumerate().map(|(index, row)| {
        if index % 2 == 0 {
            row.style(Style::new().bg(RAISED))
        } else {
            row
        }
    });
    Table::new(rows, widths)
        .header(
            Row::new(header.into_iter().map(Cell::from))
                .style(Style::new().fg(INK).bg(ACCENT).bold()),
        )
        .column_spacing(1)
}

/// Hatched fill with `text` in the middle: nothing to show yet.
fn hatched(frame: &mut Frame<'_>, area: Rect, text: &str) {
    let width = usize::from(area.width);
    let label = format!(" {text} ");
    let rows = usize::from(area.height);
    let middle = rows / 2;
    let lines: Vec<Line<'static>> = (0..rows)
        .map(|row| {
            let hatch: String = (0..width)
                .map(|column| if (column + row) % 2 == 0 { '/' } else { ' ' })
                .collect();
            if row == middle && width > label.len() + 4 {
                let side = (width - super::width_of(&label)) / 2;
                let left: String = hatch.chars().take(side).collect();
                let right: String = hatch.chars().skip(side + super::width_of(&label)).collect();
                Line::from(vec![
                    Span::raw(left).fg(LINE),
                    Span::raw(label.clone()).fg(MUTED),
                    Span::raw(right).fg(LINE),
                ])
            } else {
                Line::from(Span::raw(hatch).fg(LINE))
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

/// `→ Scope F3`: where a line leads.
fn link(text: &str) -> Span<'static> {
    Span::raw(format!("  → {text}")).fg(ACCENT)
}

/// `label       value`, the label quiet and padded to `width`.
fn row(label: &str, width: usize, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::raw(pad(label, width)).fg(MUTED)];
    spans.extend(value);
    Line::from(spans)
}

/// A segmented bar of `width` cells for `value` out of `max`: `▰` in `color`, `▱` empty.
fn segments(value: u64, max: u64, width: usize, color: Color) -> [Span<'static>; 2] {
    let max = max.max(1);
    let width_u64 = u64::try_from(width).unwrap_or(u64::MAX);
    let filled = if value == 0 {
        0
    } else {
        usize::try_from((value.min(max) * width_u64).div_ceil(max)).unwrap_or(width)
    };
    [
        Span::raw("▰".repeat(filled)).fg(color),
        Span::raw("▱".repeat(width.saturating_sub(filled))).fg(LINE),
    ]
}

/// Steps per interval as a one-line sparkline.
fn sparkline(bars: &[u64]) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let top = bars.iter().copied().max().unwrap_or(0).max(1);
    bars.iter()
        .map(|value| {
            if *value == 0 {
                '·'
            } else {
                let level = usize::try_from(value * 7 / top).unwrap_or(7);
                LEVELS.get(level).copied().unwrap_or('█')
            }
        })
        .collect()
}

/// A quiet line saying what will fill an empty panel.
fn empty(text: &str) -> Line<'static> {
    Line::from(text.to_owned()).fg(DIM)
}

// ---------- F1 Overview ----------

/// Overview, "the room": the welcome before anything happens; afterwards what to do now, the
/// activity chart, the incident, the assets, the layers and the clocks.
fn overview_page(state: &State, view: &View, now: Timestamp) -> Page {
    let quiet = state.incident.is_none() && state.pulse.is_empty();
    if quiet {
        return Page {
            columns: vec![
                vec![Panel::fill(
                    "Welcome to Cleanroom",
                    Body::Welcome,
                    &[
                        ("d", "Detonate"),
                        ("t", "Tamper"),
                        ("A", "Admit"),
                        ("F2", "Clean"),
                    ],
                )],
                vec![
                    Panel::lines("Assets", asset_lines(state), &[("F3", "Open Scope")]),
                    Panel::fill(
                        "Activity",
                        Body::Hatched("no activity yet · d detonates a scenario"),
                        &[],
                    ),
                    Panel::lines(
                        "Defense layers",
                        layer_lines(state, true),
                        &[("g", "Guardrails")],
                    ),
                ],
            ],
        };
    }
    let mut now_panel = vec![next_line(state, view, now), Line::default()];
    now_panel.extend(now_lines(state, now));
    Page {
        columns: vec![
            vec![
                Panel::lines(
                    "Now",
                    now_panel,
                    &[("a/x", "Approve/Deny"), ("↑↓", "Select")],
                ),
                Panel::fill(
                    "Activity",
                    Body::Activity,
                    &[(",/.", "Switch view"), ("F10", "Controlroom")],
                ),
            ],
            vec![
                Panel::lines("Incident", incident_lines(state), &[("F4", "Open Record")]),
                Panel::lines("Assets", asset_lines(state), &[("F3", "Open Scope")]),
                Panel::lines(
                    "Defense layers",
                    layer_lines(state, true),
                    &[("F5", "Open Defense"), ("g", "Guardrails")],
                ),
                Panel::lines(
                    "Next deadlines",
                    deadline_lines(state, now, 3),
                    &[("F4", "Open Record")],
                ),
            ],
        ],
    }
}

/// What Cleanroom is and how to start, with the name in big type.
fn welcome(frame: &mut Frame<'_>, area: Rect) {
    let [art, _, text] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area.inner(Margin::new(1, 1)));
    let big = BigText::builder()
        .pixel_size(PixelSize::Quadrant)
        .style(Style::new().fg(ACCENT))
        .lines(vec![Line::from("CLEANROOM")])
        .alignment(Alignment::Left)
        .build();
    frame.render_widget(big, art);
    let key = |key: &str, what: &str| {
        Line::from(vec![
            Span::raw("  ● ").fg(ACCENT),
            Span::raw(format!("{key:<4}")).fg(ACCENT).bold(),
            Span::raw(what.to_owned()).fg(TEXT),
        ])
    };
    let lines = vec![
        Line::from("A responder OS for the moment an attacker owns your network.").fg(BRIGHT).bold(),
        Line::from(
            "Nemotron agents investigate inside sealed strata; the kernel, not the prompt, keeps evidence read-only.",
        )
        .fg(TEXT),
        Line::from("Every command, denial and approval lands on a signed, hash-chained receipt log.").fg(MUTED),
        Line::default(),
        Line::from(Span::raw("Getting started").fg(ACCENT).bold().underlined()),
        Line::default(),
        key("t", "flip a byte in the Debian root; admission rejects it"),
        key("A", "admit the clean root again"),
        key("d", "detonate the ransomware scenario in the sacrificial stratum"),
        key("F2", "talk to Clean, the lead agent, while the team investigates"),
        key("?", "every key"),
        Line::default(),
        Line::from(vec![
            Span::raw("▌ ").fg(ACCENT),
            Span::raw("Hint: the focused panel has the bright border; [ ] or ←/→ move focus, and the bottom bar shows its keys.")
                .fg(MUTED),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
        text,
    );
}

/// `Activity | Exec | Safety`, the chart's views, the current one lit.
fn chart_tabs(current: ChartView) -> Line<'static> {
    let mut tabs = vec![Span::raw(" ")];
    for (index, (choice, name)) in [
        (ChartView::All, "Activity"),
        (ChartView::Exec, "Exec"),
        (ChartView::Safety, "Safety"),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            tabs.push(Span::raw("  |  ").fg(LINE));
        }
        if choice == current {
            tabs.push(Span::styled(
                format!(" {name} "),
                Style::new().fg(BRIGHT).bg(ACCENT_BG).bold(),
            ));
        } else {
            tabs.push(Span::raw(format!(" {name} ")).fg(DIM));
        }
    }
    Line::from(tabs)
}

/// Tool calls, OS denials and safety flags per 5 s since the investigation started, with the
/// `Activity | Exec | Safety` views as sub-tabs under it.
fn activity_chart(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View, now: Timestamp) {
    let [chart_area, tabs_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
    frame.render_widget(Paragraph::new(chart_tabs(view.chart)).centered(), tabs_area);
    if state.pulse.is_empty() {
        hatched(frame, chart_area, "no activity yet");
        return;
    }
    let [steps, denials, flags] = state.pulse.series(5, now);
    let lanes: Vec<Lane<'_>> = match view.chart {
        ChartView::All => vec![
            ("tool calls", ACCENT, &steps),
            ("OS denials", RED, &denials),
            ("safety flags", AMBER, &flags),
        ],
        ChartView::Exec => vec![
            ("tool calls", ACCENT, &steps),
            ("OS denials", RED, &denials),
        ],
        ChartView::Safety => vec![("safety flags", AMBER, &flags)],
    };
    let x_max = steps.last().map_or(5.0, |(x, _)| *x).max(5.0);
    let y_max = lanes
        .iter()
        .flat_map(|(_, _, points)| points.iter().map(|(_, y)| *y))
        .fold(1.0_f64, f64::max)
        .ceil()
        .max(2.0);
    let datasets: Vec<Dataset<'_>> = lanes
        .iter()
        .map(|(name, color, points)| {
            Dataset::default()
                .name(*name)
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(*color))
                .data(points)
        })
        .collect();
    let axis_style = Style::new().fg(DIM);
    let chart = Chart::new(datasets)
        .x_axis(
            Axis::default()
                .style(axis_style)
                .bounds([0.0, x_max])
                .labels([
                    "0s".to_owned(),
                    format!("{:.0}s", x_max / 2.0),
                    format!("{x_max:.0}s since start"),
                ]),
        )
        .y_axis(
            Axis::default()
                .title(Span::raw("per 5 s").fg(DIM))
                .style(axis_style)
                .bounds([0.0, y_max])
                .labels([
                    "0".to_owned(),
                    format!("{:.0}", y_max / 2.0),
                    format!("{y_max:.0}"),
                ]),
        )
        .legend_position(Some(ratatui::widgets::LegendPosition::TopRight))
        .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)));
    frame.render_widget(chart, chart_area);
}

/// The single most pressing next step; a signature waiting pulses.
fn next_line(state: &State, view: &View, now: Timestamp) -> Line<'static> {
    let (text, color) = match next::next_action(state, view.connected(), now) {
        NextAction::Reconnect => (
            "Lost cleanroomd. Restart it, then relaunch this console.".to_owned(),
            RED,
        ),
        NextAction::LogBroken { first_break } => (
            format!("Receipt log broken at #{first_break}: preserve it and tell counsel."),
            RED,
        ),
        NextAction::Readmit { root } => (
            format!("Tampered {root} root rejected; A admits the clean copy."),
            AMBER,
        ),
        NextAction::Approvals { count } => (
            format!("{count} waiting for your signature: a approves, x denies."),
            super::pulse_amber(view, now),
        ),
        NextAction::Clock {
            regime, remaining, ..
        } => (
            format!(
                "{} due in {}. {}",
                regime.notice(),
                clocks::short_remaining(remaining),
                regime.duty()
            ),
            urgency_color(clocks::urgency(remaining)),
        ),
        NextAction::Investigate => (
            "Incident declared: i starts the agent team.".to_owned(),
            AMBER,
        ),
        NextAction::Detonate => (
            "All clear. d detonates a scenario in the sacrificial stratum.".to_owned(),
            ACCENT,
        ),
        NextAction::Watch => (
            "Nothing needs you right now; the agents are investigating.".to_owned(),
            ACCENT,
        ),
    };
    Line::from(vec![
        Span::raw("▶ ").fg(color).bold(),
        Span::raw(text).fg(color).bold(),
    ])
}

/// What needs the commander, each with the key that acts on it.
fn now_lines(state: &State, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(Admission::Rejected { root, .. }) = &state.admission {
        lines.push(Line::from(vec![
            Span::raw(format!("tampered {root} root rejected; it never ran"))
                .fg(RED)
                .bold(),
            link("A admits the clean copy"),
        ]));
    }
    if let Some(item) = state.queue.iter().find(|item| item.sent.is_none()) {
        let what = match &item.ask {
            Ask::Tool { tool, .. } => format!("wants {tool}"),
            Ask::Proposal { action, .. } => action.clone(),
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{} ", crate::state::who_title(&item.from)))
                .fg(AMBER)
                .bold(),
            Span::raw(fit(&what, 46)).fg(TEXT),
            link("a / x"),
        ]));
    }
    let blocks = state.blocks();
    if blocks > 0 {
        lines.push(Line::from(vec![
            Span::raw(format!("{blocks} ")).fg(RED).bold(),
            Span::raw("commands blocked by the kernel").fg(TEXT),
            link("Defense F5"),
        ]));
    }
    let hit = state
        .scope
        .iter()
        .filter(|asset| compromised(asset.flags))
        .count();
    if hit > 0 {
        lines.push(Line::from(vec![
            Span::raw(format!("{hit} ")).fg(RED).bold(),
            Span::raw(format!("of {} assets compromised", state.scope.len())).fg(TEXT),
            link("Scope F3"),
        ]));
    }
    if let Some((clock, due)) = running_clocks(state).into_iter().next() {
        let left = clocks::short_remaining(due.duration_since(now));
        lines.push(Line::from(vec![
            Span::raw(format!("{left} ")).fg(AMBER).bold(),
            Span::raw(format!("to the {}", clock.regime.notice())).fg(TEXT),
            link("Record F4"),
        ]));
    }
    lines.push(Line::from(vec![
        Span::raw("ask Clean what to do first").fg(TEXT),
        link("Clean F2"),
    ]));
    lines.push(log_line(state));
    lines
}

/// The receipt log's state, with the key that verifies it.
fn log_line(state: &State) -> Line<'static> {
    match state.log {
        LogStatus::Unverified => Line::from(vec![
            Span::raw("receipt log not verified this session").fg(MUTED),
            link("v verifies"),
        ]),
        LogStatus::Intact { entries } => Line::from(vec![
            Span::raw("✓ ").fg(OK).bold(),
            Span::raw(format!("receipt log intact: {entries} signed receipts")).fg(TEXT),
        ]),
        LogStatus::Broken { first_break, .. } => Line::from(vec![
            Span::raw(format!("receipt log BROKEN at #{first_break}"))
                .fg(RED)
                .bold(),
            link("preserve the log"),
        ]),
    }
}

/// The incident record's headline fields.
fn incident_lines(state: &State) -> Vec<Line<'static>> {
    let Some(incident) = &state.incident else {
        return vec![empty("No incident declared. A detonation or i opens one.")];
    };
    let status = status_word(incident.status).to_uppercase();
    let status_color = match incident.status {
        cleanroom_proto::IncidentStatus::Detected => RED,
        cleanroom_proto::IncidentStatus::Analyzing => AMBER,
        cleanroom_proto::IncidentStatus::Contained
        | cleanroom_proto::IncidentStatus::Eradicated
        | cleanroom_proto::IncidentStatus::Recovered => OK,
        cleanroom_proto::IncidentStatus::Closed => MUTED,
    };
    let (severity, severity_color) = severity_word(incident.severity);
    vec![
        row(
            "title",
            10,
            vec![Span::raw(fit(&incident.title, 52)).fg(BRIGHT).bold()],
        ),
        row(
            "status",
            10,
            vec![
                Span::raw(status).fg(status_color).bold(),
                Span::raw("  severity ").fg(MUTED),
                Span::raw(severity).fg(severity_color).bold(),
            ],
        ),
        row(
            "detected",
            10,
            vec![
                Span::raw(state.time_label(&incident.detected_at)).fg(TEXT),
                Span::raw(format!("   {}", incident.id)).fg(DIM),
            ],
        ),
        row(
            "systems",
            10,
            vec![Span::raw(fit(&incident.affected_systems.join(", "), 52)).fg(TEXT)],
        ),
    ]
}

/// The nearest `count` running clocks, each with a bar of the time already spent.
fn deadline_lines(state: &State, now: Timestamp, count: usize) -> Vec<Line<'static>> {
    let running = running_clocks(state);
    if running.is_empty() {
        return vec![empty("No legal clock running yet.")];
    }
    running
        .into_iter()
        .take(count)
        .map(|(clock, due)| {
            let remaining = due.duration_since(now);
            let mut spans = vec![Span::raw(pad(clock.regime.notice(), 20)).fg(TEXT)];
            spans.extend(elapsed_bar(state, clock.regime, due, now, 14));
            spans.push(
                Span::raw(format!(" {:>9}", clocks::countdown(remaining)))
                    .fg(urgency_color(clocks::urgency(remaining)))
                    .bold(),
            );
            Line::from(spans)
        })
        .collect()
}

/// The share of a clock's window already spent, as `▰▰▰▱▱▱`.
fn elapsed_bar(
    state: &State,
    regime: Regime,
    due: Timestamp,
    now: Timestamp,
    width: usize,
) -> [Span<'static>; 2] {
    let triggers = state.triggers();
    let trigger = match regime {
        Regime::Gdpr => triggers.aware_at,
        Regime::Hipaa => triggers.discovered_at,
        Regime::TexasIndividuals | Regime::TexasAg => triggers.breach_determined_at,
        Regime::Sec => triggers.materiality_determined_at,
    };
    let start = trigger.and_then(|text| text.parse::<Timestamp>().ok());
    let (spent, total) = start.map_or((0, 1), |start| {
        let total = due.duration_since(start).as_secs().max(1);
        let spent = now.duration_since(start).as_secs().clamp(0, total);
        (spent, total)
    });
    let remaining = due.duration_since(now);
    segments(
        u64::try_from(spent).unwrap_or(0),
        u64::try_from(total).unwrap_or(1),
        width,
        urgency_color(clocks::urgency(remaining)),
    )
}

/// One row per asset: name, a flag strip, what happened and how many records.
fn asset_lines(state: &State) -> Vec<Line<'static>> {
    if state.scope.is_empty() {
        return vec![empty("No assets reported yet.")];
    }
    state.scope.iter().map(asset_line).collect()
}

/// `Payroll export        ███ ▒▒▒ ███ ░░░ ███  LOCKED +2   1,240`.
fn asset_line(asset: &ScopeRecord) -> Line<'static> {
    let flags = asset.flags;
    let mut spans = vec![Span::raw(pad(&asset.name, 22)).fg(BRIGHT).bold()];
    for value in [
        flags.locked,
        flags.exfiltrated,
        flags.accessed,
        flags.destroyed,
        flags.modified,
    ] {
        let (cells, color) = match value {
            Tri::Yes => ("██", RED),
            Tri::Unknown => ("▒▒", AMBER),
            Tri::No => ("░░", OK),
        };
        spans.push(Span::raw(cells).fg(color));
        spans.push(Span::raw(" "));
    }
    let hit = yes_flags(flags);
    let any_unknown = [
        flags.locked,
        flags.exfiltrated,
        flags.accessed,
        flags.destroyed,
        flags.modified,
    ]
    .contains(&Tri::Unknown);
    let (word, color) = match hit.as_slice() {
        [] if any_unknown => ("? unknown".to_owned(), AMBER),
        [] => ("✓ clean".to_owned(), OK),
        [only] => (format!("✖ {only}"), RED),
        [first, rest @ ..] => (format!("✖ {first} +{}", rest.len()), RED),
    };
    spans.push(Span::raw(pad(&word, 15)).fg(color).bold());
    spans.push(Span::raw(format!("{:>6}", grouped(asset.record_count))).fg(MUTED));
    Line::from(spans)
}

/// A segmented bar per defense layer and the guardrails setting.
fn layer_lines(state: &State, linked: bool) -> Vec<Line<'static>> {
    let counters = state.counters;
    let safety = counters.map_or(0, |counters| u64::from(counters.safety_flags));
    let model = counters.map_or(0, |counters| u64::from(counters.blocked_by_model));
    let kernel = state.blocks();
    let max = safety.max(model).max(kernel).max(5);
    let layer = |label: &str, value: u64, color: Color| {
        let mut spans = vec![Span::raw(pad(label, 16)).fg(MUTED)];
        spans.extend(segments(value, max, 20, color));
        spans.push(Span::raw(format!(" {value:>3}")).fg(color).bold());
        Line::from(spans)
    };
    let guardrails = if state.guardrails {
        Span::raw("ON  hardened prompts").fg(OK).bold()
    } else {
        Span::raw("OFF  only the kernel grant stands")
            .fg(AMBER)
            .bold()
    };
    let mut lines = vec![
        layer("safety flagged", safety, AMBER),
        layer("model refused", model, ACCENT),
        layer("kernel blocked", kernel, RED),
        row("guardrails", 16, vec![guardrails]),
    ];
    if linked {
        lines.push(Line::from(link("Defense F5")));
    }
    lines
}

// ---------- F3 Scope ----------

/// Scope, "the vault": every asset in one table, then a card each with the evidence.
fn scope_page(state: &State) -> Page {
    if state.scope.is_empty() {
        return Page {
            columns: vec![vec![Panel::fill(
                "Scope",
                Body::Hatched("no assets reported yet"),
                &[],
            )]],
        };
    }
    let table = scope_table(state);
    let mut left = vec![table];
    let mut right = Vec::new();
    for (index, asset) in state.scope.iter().enumerate() {
        let panel = Panel::lines(
            &asset.name,
            scope_card(state, asset),
            &[("F10", "Controlroom")],
        );
        if index % 2 == 0 {
            right.push(panel);
        } else {
            left.push(panel);
        }
    }
    Page {
        columns: vec![left, right],
    }
}

/// Every asset as a zebra row with its flags.
fn scope_table(state: &State) -> Panel {
    let rows: Vec<Row<'static>> = state
        .scope
        .iter()
        .map(|asset| {
            let flags = asset.flags;
            let mut cells = vec![
                Cell::from(fit(&asset.name, 20)).style(Style::new().fg(BRIGHT).bold()),
                Cell::from(Line::from(grouped(asset.record_count)).right_aligned()),
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
        })
        .collect();
    let height = u16::try_from(rows.len())
        .unwrap_or(u16::MAX)
        .saturating_add(1);
    let mut widths = vec![Constraint::Fill(1), Constraint::Length(7)];
    widths.extend([Constraint::Length(5); 5]);
    widths.push(Constraint::Length(5));
    Panel {
        title: "Assets".to_owned(),
        body: Body::Table(
            vec![
                "ASSET", "RECORDS", " LCK", " EXF", " ACC", " DST", " MOD", " CONF",
            ],
            rows,
            widths,
        ),
        rows: Some(height),
        keys: &[("F10", "Controlroom")],
    }
}

/// Every field of one asset's scope record but the flags.
fn scope_card(state: &State, asset: &ScopeRecord) -> Vec<Line<'static>> {
    let classes: Vec<&str> = asset
        .data_classes
        .iter()
        .map(|class| class_label(*class))
        .collect();
    let mut confidence = segments(u64::from(asset.confidence_pct), 100, 20, ACCENT).to_vec();
    confidence.push(Span::raw(format!(" {}%", asset.confidence_pct)).fg(TEXT));
    let key = match asset.key_exposed {
        Tri::Yes => Span::raw("key exposed").fg(RED).bold(),
        Tri::No => Span::raw("key not exposed").fg(OK),
        Tri::Unknown => Span::raw("key exposure unknown").fg(AMBER),
    };
    let evidence = if asset.evidence.is_empty() {
        "none cited yet".to_owned()
    } else {
        let more = asset.evidence.len().saturating_sub(2);
        let shown = asset
            .evidence
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if more > 0 {
            format!("{shown} +{more}")
        } else {
            shown
        }
    };
    let who = crate::state::who_title(&state.who(&asset.updated_by));
    vec![
        row("classes", 11, vec![Span::raw(classes.join(", ")).fg(TEXT)]),
        row(
            "records",
            11,
            vec![
                Span::raw(grouped(asset.record_count)).fg(BRIGHT).bold(),
                Span::raw("   Texans ").fg(MUTED),
                Span::raw(grouped(asset.texas_residents)).fg(BRIGHT).bold(),
            ],
        ),
        row("confidence", 11, confidence),
        row("key", 11, vec![key]),
        row("evidence", 11, vec![Span::raw(fit(&evidence, 52)).fg(TEXT)]),
        row(
            "updated",
            11,
            vec![Span::raw(format!("{} by {who}", state.time_label(&asset.updated_at))).fg(DIM)],
        ),
    ]
}

// ---------- F4 Record ----------

/// Record, "the ledger": the incident record, its timeline and every legal clock.
fn record_page(state: &State, now: Timestamp) -> Page {
    let mut fields = incident_lines(state);
    if let Some(incident) = &state.incident {
        fields.push(row(
            "category",
            10,
            vec![Span::raw(incident.category.clone()).fg(TEXT)],
        ));
        if !incident.summary.is_empty() {
            fields.push(Line::default());
            fields.extend(
                wrap(&incident.summary, 70)
                    .into_iter()
                    .take(4)
                    .map(|line| Line::from(line).fg(TEXT)),
            );
        }
    }
    Page {
        columns: vec![
            vec![
                Panel::lines("Incident record", fields, &[("i", "Investigate")]),
                Panel::fill("Timeline", Body::Lines(timeline_lines(state)), &[]),
            ],
            vec![Panel::lines("Legal clocks", clock_cards(state, now), &[])],
        ],
    }
}

/// The record's timeline, newest last.
fn timeline_lines(state: &State) -> Vec<Line<'static>> {
    let entries = state
        .incident
        .as_ref()
        .map(|incident| incident.timeline.as_slice())
        .unwrap_or_default();
    if entries.is_empty() {
        return vec![empty("Scribe has not written the timeline yet.")];
    }
    entries
        .iter()
        .skip(entries.len().saturating_sub(14))
        .map(|entry| {
            let who = state.who(&entry.by);
            Line::from(vec![
                Span::raw(format!("{} ", state.time_label(&entry.at))).fg(DIM),
                Span::raw(pad(&super::who_label(&who), 11)).fg(super::who_color(&who)),
                Span::raw(fit(&entry.text, 60)).fg(TEXT),
            ])
        })
        .collect()
}

/// All five clocks: the time spent as a bar, the countdown and the deadline, or why they don't
/// run.
fn clock_cards(state: &State, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for clock in clocks::clocks(&state.triggers(), &state.scope) {
        let (main, detail, color) = clock_text(&clock, now, &state.display_tz);
        lines.push(Line::from(vec![
            Span::raw(pad(clock.regime.label(), 16)).fg(BRIGHT).bold(),
            Span::raw(pad(&main, 14)).fg(color).bold(),
            Span::raw(detail).fg(DIM),
        ]));
        let mut bar = vec![Span::raw("  ")];
        if let ClockState::Running { due } = clock.state {
            bar.extend(elapsed_bar(state, clock.regime, due, now, 30));
            bar.push(
                Span::raw(format!(
                    "  {}",
                    due_label(due, &state.display_tz, "%a %b %-d")
                ))
                .fg(DIM),
            );
        } else {
            bar.push(Span::raw("▱".repeat(30)).fg(LINE));
        }
        lines.push(Line::from(bar));
        lines.push(Line::from(format!("  {}", clock.regime.duty())).fg(MUTED));
        lines.push(Line::default());
    }
    lines.pop();
    lines
}

// ---------- F5 Defense ----------

/// Defense, "the walls": the kernel-blocks count, every denial with its receipt, refusals, the
/// layers, the safety verdicts and the receipt log.
fn defense_page(state: &State) -> Page {
    let mut log = vec![log_line(state)];
    log.push(Line::from("Every exec, denial and approval is a signed, chained receipt.").fg(DIM));
    Page {
        columns: vec![
            vec![
                Panel {
                    title: "Kernel blocks".to_owned(),
                    body: Body::Hero,
                    rows: Some(6),
                    keys: &[],
                },
                denial_table(state),
                Panel::fill(
                    "Refused by the model",
                    if tagged_rows(state, "REFUSED").is_empty() {
                        Body::Hatched("no refusals yet")
                    } else {
                        Body::Lines(tagged_rows(state, "REFUSED"))
                    },
                    &[("g", "Guardrails")],
                ),
            ],
            vec![
                Panel::lines("Layers", layer_lines(state, false), &[("g", "Guardrails")]),
                verdict_table(state),
                Panel::fill(
                    "Receipt log",
                    Body::Lines(log),
                    &[("v", "Verify the chain")],
                ),
            ],
        ],
    }
}

/// The kernel-blocks count in big type, with what it means.
fn hero(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let [number, caption] =
        Layout::horizontal([Constraint::Length(20), Constraint::Fill(1)]).areas(area);
    let blocks = state.blocks();
    let big = BigText::builder()
        .pixel_size(PixelSize::Quadrant)
        .style(Style::new().fg(if blocks > 0 { RED } else { OK }))
        .lines(vec![Line::from(blocks.to_string())])
        .build();
    frame.render_widget(big, number.inner(Margin::new(1, 1)));
    let lines = vec![
        Line::default(),
        Line::from(if blocks == 1 {
            "command the kernel refused"
        } else {
            "commands the kernel refused"
        })
        .fg(BRIGHT)
        .bold(),
        Line::from("evidence is mounted read-only in every stratum;").fg(MUTED),
        Line::from("each refusal is on the signed receipt log").fg(MUTED),
    ];
    frame.render_widget(Paragraph::new(lines), caption);
}

/// Every denial as a zebra row, receipt first.
fn denial_table(state: &State) -> Panel {
    let denials = state.denials.all();
    if denials.is_empty() {
        return Panel {
            title: "Kernel denials".to_owned(),
            body: Body::Hatched("no denials yet"),
            rows: Some(3),
            keys: &[],
        };
    }
    let rows: Vec<Row<'static>> = denials
        .iter()
        .skip(denials.len().saturating_sub(10))
        .map(|denial| {
            let receipt = denial
                .receipt
                .map_or_else(|| "#?".to_owned(), |seq| format!("#{seq}"));
            let (who, color) = denial.role.map_or_else(
                || (denial.who.to_uppercase(), MUTED),
                |role| (format!("{} {}", glyph(role), role_label(role)), tint(role)),
            );
            let what = denial.command.clone();
            Row::new(vec![
                Cell::from(receipt).style(Style::new().fg(MUTED).bold()),
                Cell::from(denial.at.clone()).style(Style::new().fg(DIM)),
                Cell::from(who).style(Style::new().fg(color)),
                Cell::from(what).style(Style::new().fg(BRIGHT).bold()),
                Cell::from(denial.short_reason()).style(Style::new().fg(RED).bold()),
            ])
        })
        .collect();
    let height = u16::try_from(rows.len())
        .unwrap_or(u16::MAX)
        .saturating_add(1);
    Panel {
        title: "Kernel denials".to_owned(),
        body: Body::Table(
            vec!["RCPT", "TIME", "AGENT", "COMMAND", "WHY"],
            rows,
            vec![
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Length(13),
                Constraint::Fill(1),
                Constraint::Length(10),
            ],
        ),
        rows: Some(height),
        keys: &[("F10", "Controlroom")],
    }
}

/// The safety model's verdicts as zebra rows.
fn verdict_table(state: &State) -> Panel {
    let verdicts: Vec<&Activity> = state
        .activity
        .iter()
        .filter(|activity| activity.tag == "SAFETY")
        .collect();
    if verdicts.is_empty() {
        return Panel {
            title: "Safety verdicts".to_owned(),
            body: Body::Hatched("no verdicts yet"),
            rows: Some(3),
            keys: &[],
        };
    }
    let rows: Vec<Row<'static>> = verdicts
        .iter()
        .skip(verdicts.len().saturating_sub(8))
        .map(|activity| {
            let unsafe_verdict = activity.text.starts_with("UNSAFE");
            let (verdict, rest) = activity
                .text
                .split_once(' ')
                .unwrap_or(("", &activity.text));
            Row::new(vec![
                Cell::from(activity.at.clone()).style(Style::new().fg(DIM)),
                Cell::from(verdict.to_owned()).style(
                    Style::new()
                        .fg(if unsafe_verdict { RED } else { OK })
                        .bold(),
                ),
                Cell::from(rest.to_owned()).style(Style::new().fg(TEXT)),
            ])
        })
        .collect();
    let height = u16::try_from(rows.len())
        .unwrap_or(u16::MAX)
        .saturating_add(1);
    Panel {
        title: "Safety verdicts".to_owned(),
        body: Body::Table(
            vec!["TIME", "VERDICT", "ARTIFACT"],
            rows,
            vec![
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Fill(1),
            ],
        ),
        rows: Some(height),
        keys: &[],
    }
}

/// The newest agent-pane lines tagged `tag`.
fn tagged_rows(state: &State, tag: &str) -> Vec<Line<'static>> {
    let matching: Vec<&Activity> = state
        .activity
        .iter()
        .filter(|activity| activity.tag == tag)
        .collect();
    matching
        .iter()
        .skip(matching.len().saturating_sub(6))
        .map(|activity| {
            let (who, color) = match &activity.who {
                Who::Agent(role) => (
                    format!("{} {}", glyph(*role), role_label(*role)),
                    tint(*role),
                ),
                other @ (Who::System | Who::Me | Who::Human(_)) => (super::who_label(other), MUTED),
            };
            Line::from(vec![
                Span::raw(format!("{} ", activity.at)).fg(DIM),
                Span::raw(pad(&who, 14)).fg(color),
                Span::raw(fit(&activity.text, 48)).fg(TEXT),
            ])
        })
        .collect()
}

// ---------- F6 Team ----------

/// Team, "the crew": the Lead and its specialists as a tree with live status and activity, then a
/// card per agent with model, recent steps and findings.
fn team_page(state: &State, now: Timestamp) -> Page {
    let card = |role: Role| {
        Panel::lines(
            &format!("{} {}", glyph(role), team::title(role)),
            member_lines(state, role, now),
            &[("F2", "Ask Clean")],
        )
    };
    Page {
        columns: vec![
            vec![
                Panel::lines("Crew", crew_tree(state, now), &[("F2", "Ask Clean")]),
                card(Role::Lead),
                card(Role::Forensics),
            ],
            vec![
                card(Role::Hunter),
                card(Role::Scribe),
                card(Role::Containment),
            ],
        ],
    }
}

/// The Lead and the specialists under it, with tree guides, a status dot each, the model and
/// steps per 10 s over the last two minutes.
fn crew_tree(state: &State, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, role) in std::iter::once(Role::Lead).chain(SPECIALISTS).enumerate() {
        let status = state.team.status(role, state.waiting_on(role), now);
        let dot = match status {
            Status::Blocked => RED,
            Status::Waiting => AMBER,
            Status::Idle => DIM,
            Status::Thinking | Status::Asking(_) | Status::Running(_) | Status::Refused => ACCENT,
        };
        let guide = match index {
            0 => "",
            4 => "└─ ",
            _ => "├─ ",
        };
        let desk = state.team.desk(role);
        let model = desk.model.as_deref().map(short_model).unwrap_or_default();
        let bars = state.pulse.sparkline(role, 10, 12, now);
        lines.push(Line::from(vec![
            Span::raw(format!(" {guide}")).fg(LINE),
            Span::raw("● ").fg(dot),
            Span::raw(pad(team::title(role), 12)).fg(tint(role)).bold(),
            Span::raw(pad(&model, 14)).fg(DIM),
            Span::raw(sparkline(&bars)).fg(ACCENT),
        ]));
        let mut status_line = vec![
            Span::raw(if index == 0 || index == 4 {
                "      "
            } else {
                " │    "
            })
            .fg(LINE),
        ];
        status_line.extend(status_spans(&status, now));
        lines.push(Line::from(status_line));
    }
    lines
}

/// One agent's card: model, route, last action, recent steps and findings.
fn member_lines(state: &State, role: Role, now: Timestamp) -> Vec<Line<'static>> {
    let desk = state.team.desk(role);
    let status = state.team.status(role, state.waiting_on(role), now);
    let route = match desk.route {
        Some(cleanroom_proto::ModelRoute::Local) => " · local",
        Some(cleanroom_proto::ModelRoute::Hosted) => " · hosted",
        None => "",
    };
    let model = desk.model.as_deref().map_or_else(
        || Span::raw("not announced yet").fg(DIM),
        |model| Span::raw(format!("{}{route}", short_model(model))).fg(TEXT),
    );
    let mut lines = vec![
        row("status", 8, status_spans(&status, now)),
        row("model", 8, vec![model]),
        row(
            "last",
            8,
            vec![Span::raw(fit(desk.last.as_deref().unwrap_or("nothing yet"), 62)).fg(TEXT)],
        ),
    ];
    let mine = |activity: &&Activity| activity.who == Who::Agent(role);
    let steps: Vec<&Activity> = state
        .activity
        .iter()
        .filter(mine)
        .filter(|activity| matches!(activity.tag, "TRACE" | "ANSWER" | "BLOCKED BY OS"))
        .collect();
    for activity in steps.iter().skip(steps.len().saturating_sub(3)) {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::raw(fit(&activity.text, 66)).fg(super::tone_color(activity.tone)),
        ]));
    }
    let findings: Vec<&Activity> = state
        .activity
        .iter()
        .filter(mine)
        .filter(|activity| activity.tag == "FINDING")
        .collect();
    for finding in findings.iter().skip(findings.len().saturating_sub(2)) {
        lines.push(Line::from(vec![
            Span::raw("⚑ ").fg(AMBER),
            Span::raw(fit(&finding.text, 66)).fg(TEXT),
        ]));
    }
    lines
}

/// One chart line: legend name, color and points.
type Lane<'points> = (&'static str, Color, &'points Vec<(f64, f64)>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmented_bars_round_partial_cells_up_and_never_overflow() {
        let filled = |spans: &[Span<'static>; 2]| spans.first().map_or(0, Span::width);
        assert_eq!(filled(&segments(1, 100, 20, RED)), 1, "any count shows");
        assert_eq!(filled(&segments(0, 100, 20, RED)), 0);
        assert_eq!(filled(&segments(300, 100, 20, RED)), 20, "clamped");
        assert_eq!(sparkline(&[0, 1, 7]), "·▂█");
    }
}
