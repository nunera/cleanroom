//! The Cleanroom tabs that read the incident: Overview, Scope, Record, Defense and Team.
//!
//! Each tab lays out `✦ Title` panels in two columns. Rows are short label and value pairs, counts
//! become block bars, and `→ Scope F3` links name the key that goes there. Everything comes from
//! the bus state; an empty panel says what will fill it.

use cleanroom_proto::{Role, ScopeRecord, Tri};
use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};

use super::controlroom::class_label;
use super::lead::status_spans;
use super::{
    View, clock_text, due_label, fit, flag_look, grouped, pad, role_label, running_clocks,
    severity_word, short_model, urgency_color, wrap,
};
use crate::clocks;
use crate::denials::Kind;
use crate::next::{self, NextAction};
use crate::state::{
    Activity, Admission, Ask, LogStatus, State, Who, compromised, status_word, yes_flags,
};
use crate::team::{self, SPECIALISTS};
use crate::theme::{ACCENT, AMBER, BRIGHT, DIM, LINE, MUTED, RED, TEXT, glyph, tint};

/// A panel: its title and its lines.
type Panel = (String, Vec<Line<'static>>);

/// A `✦ Title` panel with a thin rounded border and room inside.
fn card(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(LINE))
        .title(Line::from(vec![
            Span::raw(" ✦ ").fg(ACCENT),
            Span::raw(title.to_owned()).fg(ACCENT).bold(),
            Span::raw(" "),
        ]))
        .padding(Padding::horizontal(1))
}

/// Stack `panels` down `area`, each as tall as its lines.
fn stack(frame: &mut Frame<'_>, area: Rect, panels: Vec<Panel>) {
    let constraints: Vec<Constraint> = panels
        .iter()
        .map(|(_, lines)| {
            Constraint::Length(
                u16::try_from(lines.len())
                    .unwrap_or(u16::MAX)
                    .saturating_add(2),
            )
        })
        .collect();
    let areas = Layout::vertical(constraints).spacing(1).split(area);
    for ((title, lines), cell) in panels.into_iter().zip(areas.iter()) {
        frame.render_widget(Paragraph::new(lines).block(card(&title)), *cell);
    }
}

/// Two columns of panels with a gutter, inside a margin.
fn columns(frame: &mut Frame<'_>, area: Rect, left: Vec<Panel>, right: Vec<Panel>) {
    let [_, first, _, second, _] = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area.inner(ratatui::layout::Margin::new(0, 1)));
    stack(frame, first, left);
    stack(frame, second, right);
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

/// A bar of `width` cells for `value` out of `max`: `█` filled in `color`, `░` empty.
fn bar(value: u64, max: u64, width: usize, color: Color) -> [Span<'static>; 2] {
    let max = max.max(1);
    let width_u64 = u64::try_from(width).unwrap_or(u64::MAX);
    let filled = if value == 0 {
        0
    } else {
        usize::try_from((value.min(max) * width_u64).div_ceil(max)).unwrap_or(width)
    };
    [
        Span::raw("█".repeat(filled)).fg(color),
        Span::raw("░".repeat(width.saturating_sub(filled))).fg(LINE),
    ]
}

/// A quiet line saying what will fill an empty panel.
fn empty(text: &str) -> Line<'static> {
    Line::from(text.to_owned()).fg(DIM)
}

// ---------- F1 Overview ----------

/// Overview, "the room": what to do now, the incident, the assets, the layers and the clocks.
pub(super) fn overview(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let mut now_panel = vec![next_line(state, view, now), Line::default()];
    now_panel.extend(now_lines(state, now));
    let left = vec![
        ("Now".to_owned(), now_panel),
        ("Incident".to_owned(), incident_lines(state)),
        ("Next deadlines".to_owned(), deadline_lines(state, now, 3)),
    ];
    let right = vec![
        ("Assets".to_owned(), asset_lines(state)),
        ("Defense layers".to_owned(), layer_lines(state)),
    ];
    columns(frame, area, left, right);
}

/// The single most pressing next step.
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
            AMBER,
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

/// What needs the commander, most pressing first, each with the key that acts on it.
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
        let day = due_label(due, &state.display_tz, "%a %b %-d");
        lines.push(Line::from(vec![
            Span::raw(format!("{left} ")).fg(AMBER).bold(),
            Span::raw(format!("to the {} ({day})", clock.regime.notice())).fg(TEXT),
            link("Record F4"),
        ]));
    }
    match &state.incident {
        Some(incident) if state.investigating.as_ref() != Some(&incident.id) => {
            lines.push(Line::from(vec![
                Span::raw("agents not started on this incident").fg(AMBER),
                link("i investigates"),
            ]));
        }
        Some(_) => lines.push(Line::from(vec![
            Span::raw("ask the Lead what to do first").fg(TEXT),
            link("Lead F2"),
        ])),
        None => lines.push(Line::from(vec![
            Span::raw("● ").fg(ACCENT),
            Span::raw("All clear: every asset clean, no legal clock running.").fg(TEXT),
            link("d detonates a scenario"),
        ])),
    }
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
            Span::raw("✓ ").fg(ACCENT).bold(),
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
        return vec![empty(
            "No incident declared. A detonation or a human investigate opens one.",
        )];
    };
    let status = status_word(incident.status).to_uppercase();
    let status_color = match incident.status {
        cleanroom_proto::IncidentStatus::Detected => RED,
        cleanroom_proto::IncidentStatus::Analyzing => AMBER,
        cleanroom_proto::IncidentStatus::Contained
        | cleanroom_proto::IncidentStatus::Eradicated
        | cleanroom_proto::IncidentStatus::Recovered => ACCENT,
        cleanroom_proto::IncidentStatus::Closed => MUTED,
    };
    let (severity, severity_color) = severity_word(incident.severity);
    vec![
        row("id", 11, vec![Span::raw(incident.id.clone()).fg(MUTED)]),
        row(
            "title",
            11,
            vec![Span::raw(fit(&incident.title, 58)).fg(BRIGHT).bold()],
        ),
        row(
            "status",
            11,
            vec![
                Span::raw(status).fg(status_color).bold(),
                Span::raw("  severity ").fg(MUTED),
                Span::raw(severity).fg(severity_color).bold(),
            ],
        ),
        row(
            "category",
            11,
            vec![Span::raw(incident.category.clone()).fg(TEXT)],
        ),
        row(
            "detected",
            11,
            vec![Span::raw(state.time_label(&incident.detected_at)).fg(TEXT)],
        ),
        row(
            "systems",
            11,
            vec![Span::raw(incident.affected_systems.join(", ")).fg(TEXT)],
        ),
        Line::from(link("Record F4")),
    ]
}

/// The nearest `count` running clocks.
fn deadline_lines(state: &State, now: Timestamp, count: usize) -> Vec<Line<'static>> {
    let running = running_clocks(state);
    if running.is_empty() {
        return vec![empty(
            "No legal clock running. Each starts when the record sets its trigger.",
        )];
    }
    let mut lines: Vec<Line<'static>> = running
        .into_iter()
        .take(count)
        .map(|(clock, due)| {
            let remaining = due.duration_since(now);
            Line::from(vec![
                Span::raw(pad(clock.regime.notice(), 28)).fg(TEXT),
                Span::raw(format!("{:>10}", clocks::countdown(remaining)))
                    .fg(super::urgency_color(clocks::urgency(remaining)))
                    .bold(),
                Span::raw(format!(
                    "   {}",
                    due_label(due, &state.display_tz, "%a %b %-d %H:%M")
                ))
                .fg(DIM),
            ])
        })
        .collect();
    lines.push(Line::from(link("Record F4")));
    lines
}

/// One row per asset: name, a flag strip, what happened and how many records.
fn asset_lines(state: &State) -> Vec<Line<'static>> {
    if state.scope.is_empty() {
        return vec![empty(
            "No assets reported yet; cleanroomd publishes the asset table.",
        )];
    }
    let mut lines: Vec<Line<'static>> = state.scope.iter().map(asset_line).collect();
    lines.push(Line::from(vec![
        Span::raw("strip: locked exfil accessed destroyed modified").fg(DIM),
        link("Scope F3"),
    ]));
    lines
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
            Tri::Yes => ("███", RED),
            Tri::Unknown => ("▒▒▒", AMBER),
            Tri::No => ("░░░", ACCENT),
        };
        spans.push(Span::raw(cells).fg(color));
        spans.push(Span::raw(" "));
    }
    let hit = yes_flags(flags);
    let (word, color) = match hit.as_slice() {
        [] if [
            flags.locked,
            flags.exfiltrated,
            flags.accessed,
            flags.destroyed,
            flags.modified,
        ]
        .contains(&Tri::Unknown) =>
        {
            ("unknown".to_owned(), AMBER)
        }
        [] => ("clean".to_owned(), ACCENT),
        [only] => ((*only).to_owned(), RED),
        [first, rest @ ..] => (format!("{first} +{}", rest.len()), RED),
    };
    spans.push(Span::raw(pad(&word, 14)).fg(color).bold());
    spans.push(Span::raw(format!("{:>6}", grouped(asset.record_count))).fg(MUTED));
    Line::from(spans)
}

/// A bar per defense layer and the guardrails setting.
fn layer_lines(state: &State) -> Vec<Line<'static>> {
    let counters = state.counters;
    let safety = counters.map_or(0, |counters| u64::from(counters.safety_flags));
    let model = counters.map_or(0, |counters| u64::from(counters.blocked_by_model));
    let kernel = state.blocks();
    let max = safety.max(model).max(kernel).max(5);
    let layer = |label: &str, value: u64, color: Color| {
        let mut spans = vec![Span::raw(pad(label, 16)).fg(MUTED)];
        spans.extend(bar(value, max, 20, color));
        spans.push(Span::raw(format!(" {value:>3}")).fg(color).bold());
        Line::from(spans)
    };
    let guardrails = if state.guardrails {
        Span::raw("ON  hardened prompts").fg(ACCENT).bold()
    } else {
        Span::raw("OFF  naive prompts; only the kernel grant stands")
            .fg(AMBER)
            .bold()
    };
    vec![
        layer("safety flagged", safety, AMBER),
        layer("model refused", model, ACCENT),
        layer("kernel blocked", kernel, RED),
        Line::default(),
        row("guardrails", 16, vec![guardrails]),
        Line::from(link("Defense F5")),
    ]
}

// ---------- F3 Scope ----------

/// Scope, "the vault": one card per asset with every flag and the evidence behind it.
pub(super) fn scope(frame: &mut Frame<'_>, area: Rect, state: &State) {
    if state.scope.is_empty() {
        columns(
            frame,
            area,
            vec![("Scope".to_owned(), vec![empty("No assets reported yet.")])],
            Vec::new(),
        );
        return;
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for (index, asset) in state.scope.iter().enumerate() {
        let panel = (asset.name.clone(), scope_card(state, asset));
        if index % 2 == 0 {
            left.push(panel);
        } else {
            right.push(panel);
        }
    }
    columns(frame, area, left, right);
}

/// Every field of one asset's scope record.
fn scope_card(state: &State, asset: &ScopeRecord) -> Vec<Line<'static>> {
    let flags = asset.flags;
    let mut badges = Vec::new();
    for (name, value) in [
        ("LOCKED", flags.locked),
        ("EXFIL", flags.exfiltrated),
        ("ACCESSED", flags.accessed),
        ("DESTROYED", flags.destroyed),
        ("MODIFIED", flags.modified),
    ] {
        let (word, style) = flag_look(value);
        badges.push(Span::raw(format!("{name} ")).fg(MUTED));
        badges.push(Span::styled(format!(" {word} "), style));
        badges.push(Span::raw("  "));
    }
    let classes: Vec<&str> = asset
        .data_classes
        .iter()
        .map(|class| class_label(*class))
        .collect();
    let mut confidence = bar(u64::from(asset.confidence_pct), 100, 20, ACCENT).to_vec();
    confidence.push(Span::raw(format!(" {}%", asset.confidence_pct)).fg(TEXT));
    let key = match asset.key_exposed {
        Tri::Yes => Span::raw("key exposed").fg(RED).bold(),
        Tri::No => Span::raw("key not exposed").fg(ACCENT),
        Tri::Unknown => Span::raw("key exposure unknown").fg(AMBER),
    };
    let at_rest = if asset.encrypted_at_rest {
        "encrypted at rest · "
    } else {
        "not encrypted at rest · "
    };
    let mut lines = vec![
        Line::from(badges),
        Line::default(),
        row("classes", 12, vec![Span::raw(classes.join(", ")).fg(TEXT)]),
        row(
            "records",
            12,
            vec![
                Span::raw(grouped(asset.record_count)).fg(BRIGHT).bold(),
                Span::raw("   Texans ").fg(MUTED),
                Span::raw(grouped(asset.texas_residents)).fg(BRIGHT).bold(),
            ],
        ),
        row("confidence", 12, confidence),
        row("storage", 12, vec![Span::raw(at_rest).fg(TEXT), key]),
    ];
    let evidence = if asset.evidence.is_empty() {
        vec![Span::raw("none cited yet").fg(DIM)]
    } else {
        let more = asset.evidence.len().saturating_sub(2);
        let shown = asset
            .evidence
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let text = if more > 0 {
            format!("{shown} +{more}")
        } else {
            shown
        };
        vec![Span::raw(fit(&text, 60)).fg(TEXT)]
    };
    lines.push(row("evidence", 12, evidence));
    let who = crate::state::who_title(&state.who(&asset.updated_by));
    lines.push(row(
        "updated",
        12,
        vec![Span::raw(format!("{} by {who}", state.time_label(&asset.updated_at))).fg(DIM)],
    ));
    lines
}

// ---------- F4 Record ----------

/// Record, "the ledger": the incident record, its timeline and every legal clock.
pub(super) fn record(frame: &mut Frame<'_>, area: Rect, state: &State, now: Timestamp) {
    let mut fields = incident_lines(state);
    fields.pop();
    if let Some(incident) = &state.incident
        && !incident.summary.is_empty()
    {
        fields.push(Line::default());
        fields.extend(
            wrap(&incident.summary, 70)
                .into_iter()
                .take(4)
                .map(|line| Line::from(line).fg(TEXT)),
        );
    }
    let left = vec![
        ("Incident record".to_owned(), fields),
        ("Timeline".to_owned(), timeline_lines(state)),
    ];
    let right = vec![("Legal clocks".to_owned(), clock_cards(state, now))];
    columns(frame, area, left, right);
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
        .rev()
        .take(12)
        .rev()
        .map(|entry| {
            let who = state.who(&entry.by);
            Line::from(vec![
                Span::raw(format!("{} ", state.time_label(&entry.at))).fg(DIM),
                Span::raw(pad(&super::who_label(&who), 12)).fg(super::who_color(&who)),
                Span::raw(fit(&entry.text, 64)).fg(TEXT),
            ])
        })
        .collect()
}

/// All five clocks: countdown, deadline and duty, or why they don't run.
fn clock_cards(state: &State, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for clock in clocks::clocks(&state.triggers(), &state.scope) {
        let (main, detail, color) = clock_text(&clock, now, &state.display_tz);
        lines.push(Line::from(vec![
            Span::raw(pad(clock.regime.label(), 16)).fg(BRIGHT).bold(),
            Span::raw(pad(&main, 14)).fg(color).bold(),
            Span::raw(detail).fg(DIM),
        ]));
        lines.push(Line::from(format!("  {}", clock.regime.duty())).fg(MUTED));
        lines.push(Line::default());
    }
    lines.pop();
    lines
}

// ---------- F5 Defense ----------

/// Defense, "the walls": every kernel denial, refusal and safety verdict, and the receipt log.
pub(super) fn defense(frame: &mut Frame<'_>, area: Rect, state: &State) {
    let left = vec![
        ("Kernel denials".to_owned(), denial_lines(state)),
        (
            "Refused by the model".to_owned(),
            tagged(state, "REFUSED", 6),
        ),
    ];
    let mut log = vec![log_line(state)];
    log.push(Line::from("Every exec, denial and approval is a signed, chained receipt.").fg(DIM));
    let right = vec![
        ("Layers".to_owned(), layer_lines(state)),
        ("Safety verdicts".to_owned(), tagged(state, "SAFETY", 8)),
        ("Receipt log".to_owned(), log),
    ];
    columns(frame, area, left, right);
}

/// One line per denial, receipt first.
fn denial_lines(state: &State) -> Vec<Line<'static>> {
    let denials = state.denials.all();
    if denials.is_empty() {
        return vec![empty(
            "None yet. Every agent command runs under its stratum's grant.",
        )];
    }
    denials
        .iter()
        .rev()
        .take(12)
        .rev()
        .map(|denial| {
            let receipt = denial
                .receipt
                .map_or_else(|| "  #?".to_owned(), |seq| format!("#{seq:<3}"));
            let who = denial.role.map_or_else(
                || pad(&denial.who.to_uppercase(), 13),
                |role| pad(&format!("{} {}", glyph(role), role_label(role)), 13),
            );
            let what = match denial.kind {
                Kind::Exec => format!("exec {}", denial.command),
                Kind::Record => denial.command.clone(),
            };
            Line::from(vec![
                Span::raw(format!("{receipt} ")).fg(MUTED).bold(),
                Span::raw(format!("{} ", denial.at)).fg(DIM),
                Span::raw(who).fg(denial.role.map_or(MUTED, tint)),
                Span::raw(pad(&fit(&what, 34), 35)).fg(BRIGHT).bold(),
                Span::raw(denial.short_reason()).fg(RED).bold(),
            ])
        })
        .collect()
}

/// The newest `count` agent-pane lines tagged `tag`.
fn tagged(state: &State, tag: &str, count: usize) -> Vec<Line<'static>> {
    let matching: Vec<&Activity> = state
        .activity
        .iter()
        .filter(|activity| activity.tag == tag)
        .collect();
    if matching.is_empty() {
        return vec![empty("None yet.")];
    }
    matching
        .iter()
        .skip(matching.len().saturating_sub(count))
        .map(|activity| activity_line(activity))
        .collect()
}

/// `01:20:31 ▲ HUNTER  text`.
fn activity_line(activity: &Activity) -> Line<'static> {
    let (who, color) = match &activity.who {
        Who::Agent(role) => (
            format!("{} {}", glyph(*role), role_label(*role)),
            tint(*role),
        ),
        other @ (Who::System | Who::Me | Who::Human(_)) => (super::who_label(other), MUTED),
    };
    let text_color = super::tone_color(activity.tone);
    Line::from(vec![
        Span::raw(format!("{} ", activity.at)).fg(DIM),
        Span::raw(pad(&who, 14)).fg(color),
        Span::raw(fit(&activity.text, 48)).fg(if text_color == DIM { MUTED } else { TEXT }),
    ])
}

// ---------- F6 Team ----------

/// Team, "the crew": the Lead and each specialist with model, status, recent steps and findings.
pub(super) fn crew(frame: &mut Frame<'_>, area: Rect, state: &State, now: Timestamp) {
    let mut left = vec![member_panel(state, Role::Lead, now)];
    let mut right = Vec::new();
    for (index, role) in SPECIALISTS.into_iter().enumerate() {
        if index % 2 == 0 {
            right.push(member_panel(state, role, now));
        } else {
            left.push(member_panel(state, role, now));
        }
    }
    columns(frame, area, left, right);
}

/// One agent's card.
fn member_panel(state: &State, role: Role, now: Timestamp) -> Panel {
    let desk = state.team.desk(role);
    let status = state.team.status(role, state.waiting_on(role), now);
    let model = desk.model.as_deref().map_or_else(
        || Span::raw("not announced on the bus yet").fg(DIM),
        |model| Span::raw(format!("{}  ({model})", short_model(model))).fg(TEXT),
    );
    let route = match desk.route {
        Some(cleanroom_proto::ModelRoute::Local) => "local model",
        Some(cleanroom_proto::ModelRoute::Hosted) => "hosted model",
        None => "—",
    };
    let link = match role {
        Role::Lead => "talks to you and asks the specialists".to_owned(),
        Role::Hunter | Role::Forensics | Role::Scribe | Role::Containment => {
            if state.team.link(role, now) {
                "the Lead is waiting on its answer".to_owned()
            } else {
                "reports to the Lead".to_owned()
            }
        }
    };
    let mut lines = vec![
        row("status", 10, status_spans(&status, now)),
        row("model", 10, vec![model]),
        row("route", 10, vec![Span::raw(route).fg(TEXT)]),
        row("link", 10, vec![Span::raw(link).fg(MUTED)]),
        row(
            "last",
            10,
            vec![Span::raw(fit(desk.last.as_deref().unwrap_or("nothing yet"), 64)).fg(TEXT)],
        ),
    ];
    let mine = |activity: &&Activity| activity.who == Who::Agent(role);
    let steps: Vec<&Activity> = state
        .activity
        .iter()
        .filter(mine)
        .filter(|activity| matches!(activity.tag, "TRACE" | "ANSWER" | "BLOCKED BY OS"))
        .collect();
    for activity in steps.iter().rev().take(3).rev() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::raw(fit(&activity.text, 70)).fg(super::tone_color(activity.tone)),
        ]));
    }
    let findings: Vec<&Activity> = state
        .activity
        .iter()
        .filter(mine)
        .filter(|activity| activity.tag == "FINDING")
        .collect();
    for finding in findings.iter().rev().take(2).rev() {
        lines.push(Line::from(vec![
            Span::raw("⚑ ").fg(AMBER),
            Span::raw(fit(&finding.text, 70)).fg(TEXT),
        ]));
    }
    (format!("{} {}", glyph(role), team::title(role)), lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_round_partial_cells_up_and_never_overflow() {
        let width = |spans: &[Span<'static>; 2]| spans.iter().map(Span::width).sum::<usize>();
        let filled = |spans: &[Span<'static>; 2]| spans.first().map_or(0, Span::width);
        assert_eq!(filled(&bar(1, 100, 20, RED)), 1, "any count shows");
        assert_eq!(filled(&bar(0, 100, 20, RED)), 0);
        assert_eq!(filled(&bar(300, 100, 20, RED)), 20, "clamped");
        assert_eq!(width(&bar(7, 9, 20, RED)), 20);
    }
}
