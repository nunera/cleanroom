//! The System tab, "the machine": the OS underneath the agents, from cleanroomd's status lines.
//!
//! The roots as layer stacks with their digests, each stratum as a double wall labelled with what
//! the grant shuts out, the commands run and denied inside it, the evidence seal, and the receipt
//! chain as linked blocks across the width.

use cleanroom_proto::Role;
use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};

use super::{View, fit};
use crate::state::{Activity, LogStatus, State, Who};
use crate::team::Status;
use crate::theme::{
    ACCENT, AMBER, BRIGHT, DIM, FOCUS, LINE, MUTED, OK, RAISED_HI, RED, TEXT, glyph, tint,
};

/// What cleanroomd last said about a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootState {
    /// Nothing this session: pinned, admitted on first use.
    Pinned,
    /// Admitted.
    Admitted,
    /// A byte was flipped in the staged copy.
    Tampered,
    /// Admission failed its lock.
    Rejected,
}

/// A root as the status lines describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RootView {
    /// The latest state.
    pub(super) state: RootState,
    /// The unpacked tree's digest, once admitted.
    pub(super) tree: Option<String>,
    /// The manifest digest, once admitted.
    pub(super) manifest: Option<String>,
    /// A layer digest named by a tamper or a rejection.
    pub(super) layer: Option<String>,
    /// Local `HH:MM:SS` of the last admission.
    pub(super) at: Option<String>,
}

/// The first `sha256:…` digest after `marker` in `text`.
fn digest_after(text: &str, marker: &str) -> Option<String> {
    let (_, rest) = text.split_once(marker)?;
    let digest: String = rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == ':')
        .collect();
    digest.starts_with("sha256:").then_some(digest)
}

/// `root` after every status line in `lines`, oldest first.
pub(super) fn root_view<'a>(
    root: &str,
    lines: impl Iterator<Item = (&'a str, &'a str)>,
) -> RootView {
    let admitted = format!("root {root} admitted:");
    let rejected = format!("root {root} REJECTED");
    let tampered = format!("in the staged copy of {root};");
    let mut view = RootView {
        state: RootState::Pinned,
        tree: None,
        manifest: None,
        layer: None,
        at: None,
    };
    for (at, text) in lines {
        if text.starts_with(&admitted) {
            view.state = RootState::Admitted;
            view.manifest = digest_after(text, "manifest");
            view.tree = digest_after(text, "unpacked tree");
            view.at = Some(at.to_owned());
        } else if text.starts_with(&rejected) {
            view.state = RootState::Rejected;
            view.layer = digest_after(text, "layer").or(view.layer);
        } else if text.contains(&tampered) {
            view.state = RootState::Tampered;
            view.layer = digest_after(text, "layer").or(view.layer);
        }
    }
    view
}

/// The first `receipt #N` in `text`.
pub(super) fn receipt_in(text: &str) -> Option<u64> {
    let (_, rest) = text.split_once("receipt #")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// What a receipted status line records, in one word.
pub(super) fn receipt_kind(text: &str) -> &'static str {
    if text.starts_with("OS denied") {
        "deny"
    } else if text.contains(" admitted:") {
        "admit"
    } else if text.contains("REJECTED") {
        "reject"
    } else if text.contains("flipped byte") {
        "tamper"
    } else if text.contains("detonated") {
        "detonate"
    } else if text.starts_with("evidence sealed") {
        "seal"
    } else if text.contains("approved") {
        "approve"
    } else if text.contains("denied proposal") || text.contains("declined") {
        "decline"
    } else {
        "event"
    }
}

/// cleanroomd's status lines, oldest first, as `(HH:MM:SS, text)`.
fn statuses(state: &State) -> Vec<(&str, &str)> {
    state
        .activity
        .iter()
        .filter(|activity| activity.tag == "STATUS" && activity.who == Who::System)
        .map(|activity| (activity.at.as_str(), activity.text.as_str()))
        .collect()
}

/// `sha256:707ae956…4e3c`.
fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let head: String = hex.chars().take(10).collect();
    let tail: Vec<char> = hex.chars().rev().take(4).collect();
    let tail: String = tail.into_iter().rev().collect();
    format!("sha256:{head}…{tail}")
}

/// A rounded panel titled `title` in `color`.
fn card(title: Line<'static>, color: Color) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(title)
        .padding(Padding::horizontal(1))
}

/// ` ◆ name `, a panel title.
fn heading(name: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(" ◆ ").fg(ACCENT),
        Span::raw(format!("{name} ")).fg(BRIGHT).bold(),
    ])
}

/// Draw the System tab into `area`; the view is unused because the tab has no selection.
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    _view: &View,
    now: Timestamp,
) {
    let lines = statuses(state);
    let area = area.inner(Margin::new(1, 1));
    let [top, _, strata, legend, _, chain] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(6),
    ])
    .areas(area);
    let [debian, alpine, seal] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Fill(1),
    ])
    .spacing(2)
    .areas(top);
    render_root(frame, debian, "debian", &lines);
    render_root(frame, alpine, "alpine", &lines);
    render_seal(frame, seal, &lines);
    render_strata(frame, strata, state, &lines, now);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("  ═ ").fg(ACCENT),
            Span::raw("walls declared by the grant; ").fg(DIM),
            Span::raw("cleanroomd probe").fg(MUTED).bold(),
            Span::raw(" proves them").fg(DIM),
        ])),
        legend,
    );
    render_chain(frame, chain, state, &lines);
}

/// One root as a stack of three thin bars: unpacked tree, manifest and the layers, each with its
/// short digest.
fn render_root(frame: &mut Frame<'_>, area: Rect, root: &str, lines: &[(&str, &str)]) {
    let view = root_view(root, lines.iter().copied());
    let (word, color) = match view.state {
        RootState::Pinned => ("pinned · admitted on first use".to_owned(), MUTED),
        RootState::Admitted => (
            format!("✓ admitted {}", view.at.clone().unwrap_or_default()),
            OK,
        ),
        RootState::Tampered => ("! tampered copy staged".to_owned(), AMBER),
        RootState::Rejected => ("✖ rejected by its lock".to_owned(), RED),
    };
    let title = Line::from(vec![
        Span::raw(" ◇ ").fg(ACCENT),
        Span::raw(format!("root {root} ")).fg(BRIGHT).bold(),
    ]);
    let block = card(
        title,
        if view.state == RootState::Rejected {
            RED
        } else {
            LINE
        },
    )
    .title(Line::from(Span::raw(format!(" {word} ")).fg(color).bold()).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let bar_width = usize::from(inner.width).saturating_sub(34).clamp(6, 18);
    let layer_color = match view.state {
        RootState::Rejected => RED,
        RootState::Tampered => AMBER,
        RootState::Admitted => ACCENT,
        RootState::Pinned => LINE,
    };
    let solid = if view.state == RootState::Pinned {
        LINE
    } else {
        ACCENT
    };
    let bar = |label: &str, digest: Option<&String>, color: Color| {
        Line::from(vec![
            Span::raw("▆".repeat(bar_width)).fg(color),
            Span::raw(format!(" {label:<9}")).fg(MUTED),
            Span::raw(digest.map_or_else(|| "pinned".to_owned(), |digest| short_digest(digest)))
                .fg(if digest.is_some() { TEXT } else { DIM }),
        ])
    };
    let stack = vec![
        bar("tree", view.tree.as_ref(), solid),
        bar("manifest", view.manifest.as_ref(), solid),
        bar("layers", view.layer.as_ref(), layer_color),
        Line::default(),
        Line::from("OCI layers pinned in the lock; admission checks every digest").fg(DIM),
    ];
    frame.render_widget(Paragraph::new(stack), inner);
}

/// The evidence seal: digest, files, and how often a denial confirmed it unchanged.
fn render_seal(frame: &mut Frame<'_>, area: Rect, lines: &[(&str, &str)]) {
    let sealed = lines
        .iter()
        .find(|(_, text)| text.starts_with("evidence sealed"));
    let verified = lines
        .iter()
        .rev()
        .find(|(_, text)| text.starts_with("evidence verified"));
    let unchanged = lines
        .iter()
        .filter(|(_, text)| text.contains("evidence unchanged"))
        .count();
    let Some((at, text)) = sealed else {
        let body =
            Line::from("Not sealed yet: cleanroomd seals the evidence at detection.").fg(DIM);
        frame.render_widget(
            Paragraph::new(body).block(card(heading("evidence seal"), LINE)),
            area,
        );
        return;
    };
    let digest = digest_after(text, "detection:")
        .map(|digest| short_digest(&digest))
        .unwrap_or_default();
    let files = text
        .split_once(" over ")
        .and_then(|(_, rest)| rest.split(" files").next())
        .unwrap_or("?");
    let receipt = receipt_in(text)
        .map(|seq| format!("#{seq}"))
        .unwrap_or_default();
    let mut body = vec![
        Line::from(vec![
            Span::raw("▣ ").fg(ACCENT),
            Span::raw(digest).fg(BRIGHT).bold(),
        ]),
        Line::from(
            Span::raw(format!("  {files} files · sealed {at} · receipt {receipt}")).fg(MUTED),
        ),
        Line::default(),
        Line::from(vec![
            Span::raw("✓ ").fg(OK).bold(),
            Span::raw(format!("unchanged since {receipt}"))
                .fg(TEXT)
                .bold(),
            Span::raw(format!(
                " · {unchanged} denied command{} checked it",
                if unchanged == 1 { "" } else { "s" }
            ))
            .fg(MUTED),
        ]),
    ];
    if let Some((at, _)) = verified {
        body.push(Line::from(vec![
            Span::raw("✓ ").fg(OK).bold(),
            Span::raw(format!("verified {at}: every file matches")).fg(TEXT),
        ]));
    }
    frame.render_widget(
        Paragraph::new(body).block(card(heading("evidence seal"), FOCUS)),
        area,
    );
}

/// A stratum: name, root, whose it is and the walls on its edges.
struct Stratum {
    /// Name.
    name: &'static str,
    /// The root it runs on, or what it is for.
    root: &'static str,
    /// The agent that runs in it.
    role: Option<Role>,
    /// Walls: top right, bottom left, bottom right.
    walls: [&'static str; 3],
}

/// Every stratum that runs commands.
const STRATA: [Stratum; 4] = [
    Stratum {
        name: "hunter",
        root: "debian",
        role: Some(Role::Hunter),
        walls: ["net ✕  caps ✕", "userns ✕", "evidence RO · scratch RW"],
    },
    Stratum {
        name: "forensics",
        root: "alpine",
        role: Some(Role::Forensics),
        walls: ["net ✕  caps ✕", "userns ✕", "evidence RO · scratch RW"],
    },
    Stratum {
        name: "acme-fs",
        root: "debian · victim",
        role: None,
        walls: ["net ✕", "root RO", "share RW"],
    },
    Stratum {
        name: "rule-check",
        root: "yara rules",
        role: None,
        walls: ["net ✕  caps ✕", "userns ✕", "rules RO"],
    },
];

/// The strata as double-walled boxes, then the agents that run no commands.
fn render_strata(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    lines: &[(&str, &str)],
    now: Timestamp,
) {
    let [boxes, _, quiet] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .areas(area);
    let cells = Layout::horizontal([Constraint::Fill(1); 4])
        .spacing(2)
        .split(boxes);
    for (stratum, cell) in STRATA.iter().zip(cells.iter()) {
        render_stratum(frame, *cell, (state, now), stratum, lines);
    }
    let roles = [Role::Scribe, Role::Containment, Role::Lead];
    let cells = Layout::horizontal([Constraint::Fill(1); 3])
        .spacing(2)
        .split(quiet);
    for (role, cell) in roles.into_iter().zip(cells.iter()) {
        let title = Line::from(vec![
            Span::raw(format!(" {} ", glyph(role))).fg(tint(role)),
            Span::raw(format!("{} ", crate::team::title(role).to_lowercase()))
                .fg(BRIGHT)
                .bold(),
        ]);
        let body = Line::from(vec![
            Span::raw("no exec").fg(MUTED).bold(),
            Span::raw(" · asks, records and proposes over the bus").fg(DIM),
        ]);
        frame.render_widget(Paragraph::new(body).block(card(title, LINE)), *cell);
    }
}

/// Commands run and denied in `stratum`, whether a denial there is fresh, and its last command.
fn counts(
    state: &State,
    stratum: &Stratum,
    lines: &[(&str, &str)],
    now: Timestamp,
) -> (usize, usize, bool, String) {
    let Some(role) = stratum.role else {
        let needle = if stratum.name == "acme-fs" {
            "detonated"
        } else {
            "rule-check"
        };
        let mine: Vec<&str> = lines
            .iter()
            .filter(|(_, text)| text.contains(needle))
            .map(|(_, text)| *text)
            .collect();
        let last = mine
            .last()
            .map_or_else(String::new, |text| (*text).to_owned());
        return (mine.len(), 0, false, last);
    };
    let traces: Vec<&Activity> = state
        .activity
        .iter()
        .filter(|activity| activity.who == Who::Agent(role))
        .filter(|activity| activity.tag == "TRACE" && activity.text.contains(" exec "))
        .collect();
    let denied = state
        .denials
        .all()
        .iter()
        .filter(|denial| denial.role == Some(role))
        .count();
    let flashing = state.team.status(role, state.waiting_on(role), now) == Status::Blocked;
    let last = traces
        .last()
        .map_or_else(String::new, |activity| activity.text.clone());
    (traces.len(), denied, flashing, last)
}

/// One stratum: a double wall labelled on its edges, the commands run and denied inside, red
/// while a denial is fresh.
fn render_stratum(
    frame: &mut Frame<'_>,
    area: Rect,
    (state, now): (&State, Timestamp),
    stratum: &Stratum,
    lines: &[(&str, &str)],
) {
    let (run, denied, flashing, last) = counts(state, stratum, lines, now);
    let wall = if flashing { RED } else { ACCENT };
    let mut name = vec![Span::raw(" ")];
    if let Some(role) = stratum.role {
        name.push(Span::raw(format!("{} ", glyph(role))).fg(tint(role)));
    }
    name.push(Span::raw(stratum.name).fg(BRIGHT).bold());
    name.push(Span::raw(format!(" · {} ", stratum.root)).fg(MUTED));
    let [top_right, bottom_left, bottom_right] = stratum.walls;
    let edge = |text: &str| Span::raw(format!(" {text} ")).fg(wall).bold();
    let block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(Style::new().fg(wall))
        .title(Line::from(name))
        .title(Line::from(edge(top_right)).right_aligned())
        .title_bottom(Line::from(edge(bottom_left)))
        .title_bottom(Line::from(edge(bottom_right)).right_aligned())
        .padding(Padding::new(2, 2, 1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width);
    let unit = match (stratum.role, stratum.name) {
        (Some(_), _) => "commands",
        (None, "acme-fs") => "detonations",
        (None, _) => "rule checks",
    };
    let total = run.max(1);
    let bar = width.saturating_sub(1);
    let filled = (bar * run.min(total)).checked_div(total).unwrap_or(0);
    let red = (bar * denied.min(total)).checked_div(total).unwrap_or(0);
    let mut body = vec![
        Line::from(vec![
            Span::raw(format!("{run}")).fg(BRIGHT).bold(),
            Span::raw(format!(" {unit} run    ")).fg(MUTED),
            Span::raw(format!("{denied}"))
                .fg(if denied > 0 { RED } else { OK })
                .bold(),
            Span::raw(" denied by the kernel").fg(MUTED),
        ]),
        Line::from(vec![
            Span::raw("█".repeat(filled.saturating_sub(red))).fg(ACCENT),
            Span::raw("█".repeat(red)).fg(RED),
            Span::raw("░".repeat(bar.saturating_sub(filled))).fg(LINE),
        ]),
        Line::default(),
    ];
    if flashing {
        body.push(Line::from(Span::styled(
            " DENIED ",
            Style::new().fg(BRIGHT).bg(RED).bold(),
        )));
    }
    body.push(if last.is_empty() {
        Line::from("nothing run yet").fg(DIM)
    } else {
        Line::from(fit(&crate::state::one_line(&last), width)).fg(DIM)
    });
    frame.render_widget(Paragraph::new(body), inner);
}

/// Whether the chain verified: this console's check, else cleanroomd's last word on it.
fn chain_verdict(state: &State, lines: &[(&str, &str)]) -> Span<'static> {
    match state.log {
        LogStatus::Intact { entries } => {
            Span::raw(format!("✓ chain verified: {entries} receipts intact"))
                .fg(OK)
                .bold()
        }
        LogStatus::Broken { first_break, .. } => {
            Span::raw(format!("✖ chain BROKEN at #{first_break}"))
                .fg(RED)
                .bold()
        }
        LogStatus::Unverified => lines
            .iter()
            .rev()
            .find(|(_, text)| text.starts_with("receipt log verified"))
            .map_or_else(
                || Span::raw("not verified this session · v verifies").fg(DIM),
                |(_, text)| Span::raw(format!("✓ {text}")).fg(OK).bold(),
            ),
    }
}

/// The color of a receipt of `kind`.
fn kind_color(kind: &str) -> Color {
    match kind {
        "deny" | "reject" => RED,
        "tamper" => AMBER,
        "approve" | "admit" | "seal" => OK,
        _ => ACCENT,
    }
}

/// The receipt chain: the newest receipts as linked blocks across the width, and the verdict.
fn render_chain(frame: &mut Frame<'_>, area: Rect, state: &State, lines: &[(&str, &str)]) {
    let mut receipts: Vec<(u64, &'static str)> = lines
        .iter()
        .filter(|(_, text)| !text.starts_with("evidence verified"))
        .filter_map(|(_, text)| receipt_in(text).map(|seq| (seq, receipt_kind(text))))
        .collect();
    receipts.sort_unstable();
    receipts.dedup_by_key(|(seq, _)| *seq);
    let block = card(heading("receipt chain"), LINE).title(
        Line::from(vec![
            Span::raw(" "),
            chain_verdict(state, lines),
            Span::raw(" "),
        ])
        .right_aligned(),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width);
    let fits = (width + 3) / 13;
    let shown: Vec<(u64, &str)> = receipts
        .iter()
        .skip(receipts.len().saturating_sub(fits))
        .copied()
        .collect();
    let count = shown.len();
    if count == 0 {
        frame.render_widget(
            Paragraph::new(Line::from("No receipts on the bus yet.").fg(DIM)),
            inner,
        );
        return;
    }
    let chip = ((width + 3) / count).saturating_sub(3).clamp(10, 22);
    let mut rows: [Vec<Span<'static>>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for (index, (seq, kind)) in shown.into_iter().enumerate() {
        let joins = if index > 0 {
            ["   ", "─◆─", "   ", "   "]
        } else {
            ["", "", "", ""]
        };
        for (row, join) in rows.iter_mut().zip(joins) {
            row.push(Span::raw(join).fg(ACCENT));
        }
        let inside = chip.saturating_sub(2);
        let [top, number, word, bottom] = &mut rows;
        top.push(Span::raw(format!("╭{}╮", "─".repeat(inside))).fg(LINE));
        number.push(Span::raw("│").fg(LINE));
        number.push(Span::styled(
            format!(
                " {:<width$}",
                format!("#{seq}"),
                width = inside.saturating_sub(1)
            ),
            Style::new().fg(BRIGHT).bg(RAISED_HI).bold(),
        ));
        number.push(Span::raw("│").fg(LINE));
        word.push(Span::raw("│").fg(LINE));
        word.push(
            Span::raw(format!(" {kind:<width$}", width = inside.saturating_sub(1)))
                .fg(kind_color(kind)),
        );
        word.push(Span::raw("│").fg(LINE));
        bottom.push(Span::raw(format!("╰{}╯", "─".repeat(inside))).fg(LINE));
    }
    let chain: Vec<Line<'static>> = rows.into_iter().map(Line::from).collect();
    frame.render_widget(Paragraph::new(chain), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_give_root_stacks_receipts_and_kinds() {
        let lines = [
            (
                "15:19:01",
                "commander ab flipped byte 9 of layer sha256:dd05 in the staged copy of debian; the next admission checks it (receipt #5)",
            ),
            (
                "15:19:02",
                "root debian REJECTED: layer sha256:dd05 does not match its lock (receipt #6)",
            ),
            (
                "15:19:05",
                "root debian admitted: manifest sha256:c67e92c8, unpacked tree sha256:f1d5 (receipt #7)",
            ),
        ];
        let debian = root_view("debian", lines.iter().copied());
        assert_eq!(debian.state, RootState::Admitted);
        assert_eq!(debian.manifest.as_deref(), Some("sha256:c67e92c8"));
        assert_eq!(debian.tree.as_deref(), Some("sha256:f1d5"));
        assert_eq!(debian.layer.as_deref(), Some("sha256:dd05"));
        assert_eq!(debian.at.as_deref(), Some("15:19:05"));
        assert_eq!(
            root_view("alpine", lines.iter().copied()).state,
            RootState::Pinned
        );
        assert_eq!(
            root_view("debian", lines.iter().take(2).copied()).state,
            RootState::Rejected
        );
        let denied = "OS denied hunter: `sh -c rm -rf /evidence/*`: evidence is mounted read_only for hunter (receipt #45); evidence unchanged: still matches the seal from receipt #10";
        assert_eq!(
            receipt_in(denied),
            Some(45),
            "the first receipt, not the seal's"
        );
        assert_eq!(receipt_kind(denied), "deny");
    }
}
