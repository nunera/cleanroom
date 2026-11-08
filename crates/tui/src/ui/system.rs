//! The System tab, "the machine": the OS underneath the agents, from cleanroomd's status lines.
//!
//! The admitted roots and their manifests, one box per stratum drawn as its walls with the
//! commands run and denied inside it, the evidence seal, and the receipt chain as linked blocks.

use cleanroom_proto::Role;
use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};

use super::{View, pad};
use crate::state::{Activity, LogStatus, State, Who};
use crate::team::Status;
use crate::theme::{
    ACCENT, AMBER, BRIGHT, DIM, FOCUS, LINE, MUTED, OK, RAISED_HI, RED, TEXT, glyph, tint,
};

/// What cleanroomd last said about a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RootState {
    /// Nothing this session.
    Unknown,
    /// Admitted with this manifest digest at this time, under this receipt.
    Admitted {
        /// Manifest digest.
        manifest: String,
        /// Local `HH:MM:SS`.
        at: String,
    },
    /// A byte was flipped in the staged copy.
    Tampered,
    /// Admission failed its lock.
    Rejected,
}

/// The state of `root` after every status line in `lines`, oldest first.
pub(super) fn root_state<'a>(
    root: &str,
    lines: impl Iterator<Item = (&'a str, &'a str)>,
) -> RootState {
    let admitted = format!("root {root} admitted: manifest ");
    let rejected = format!("root {root} REJECTED");
    let tampered = format!("in the staged copy of {root};");
    let mut state = RootState::Unknown;
    for (at, text) in lines {
        if let Some(rest) = text.strip_prefix(&admitted) {
            let manifest = rest.split([',', ' ']).next().unwrap_or_default().to_owned();
            state = RootState::Admitted {
                manifest,
                at: at.to_owned(),
            };
        } else if text.starts_with(&rejected) {
            state = RootState::Rejected;
        } else if text.contains(&tampered) {
            state = RootState::Tampered;
        }
    }
    state
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
    } else if text.contains(" admitted: ") {
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

/// A rounded box titled `title`, its border `color`.
fn card(title: Line<'static>, color: Color) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(title)
        .padding(Padding::horizontal(1))
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
    let [top, _, strata, _, chain] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(7),
    ])
    .areas(area);
    let [debian, alpine, seal] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Fill(2),
    ])
    .spacing(2)
    .areas(top);
    render_root(frame, debian, "debian", &lines);
    render_root(frame, alpine, "alpine", &lines);
    render_seal(frame, seal, &lines);
    render_strata(frame, strata, state, &lines, now);
    render_chain(frame, chain, state, &lines);
}

/// One root: its state, manifest digest and when it was last admitted.
fn render_root(frame: &mut Frame<'_>, area: Rect, root: &str, lines: &[(&str, &str)]) {
    let state = root_state(root, lines.iter().copied());
    let (word, color) = match &state {
        RootState::Unknown => ("not admitted this session", DIM),
        RootState::Admitted { .. } => ("✓ ADMITTED", OK),
        RootState::Tampered => ("! TAMPERED, awaiting admission", AMBER),
        RootState::Rejected => ("✖ REJECTED by its lock", RED),
    };
    let title = Line::from(vec![
        Span::raw(" ◇ ").fg(ACCENT),
        Span::raw(format!("root {root} ")).fg(BRIGHT).bold(),
    ]);
    let mut body = vec![
        Line::from(Span::raw(word).fg(color).bold()),
        Line::default(),
    ];
    match &state {
        RootState::Admitted { manifest, at } => {
            body.push(Line::from(vec![
                Span::raw("manifest ").fg(MUTED),
                Span::raw(short_digest(manifest)).fg(TEXT),
            ]));
            body.push(Line::from(vec![
                Span::raw("admitted ").fg(MUTED),
                Span::raw(at.clone()).fg(TEXT),
            ]));
        }
        RootState::Unknown | RootState::Tampered | RootState::Rejected => {
            body.push(Line::from("pinned OCI layers, checked against the lock").fg(DIM));
        }
    }
    let border = if matches!(state, RootState::Rejected) {
        RED
    } else {
        LINE
    };
    frame.render_widget(Paragraph::new(body).block(card(title, border)), area);
}

/// `sha256:707ae956…4e3c`.
fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let head: String = hex.chars().take(10).collect();
    let tail: String = hex
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("sha256:{head}…{tail}")
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
    let title = Line::from(vec![
        Span::raw(" ◆ ").fg(ACCENT),
        Span::raw("evidence seal ").fg(BRIGHT).bold(),
    ]);
    let body = sealed.map_or_else(
        || vec![Line::from("No seal yet: cleanroomd seals the evidence when an incident is detected.").fg(DIM)],
        |(at, text)| {
            let digest = text
                .split_whitespace()
                .find(|word| word.starts_with("sha256:"))
                .map(short_digest)
                .unwrap_or_default();
            let files = text
                .split_once(" over ")
                .and_then(|(_, rest)| rest.split(" files").next())
                .unwrap_or("?");
            let seal_receipt = receipt_in(text)
                .map(|seq| format!("#{seq}"))
                .unwrap_or_default();
            let mut body = vec![
                Line::from(vec![
                    Span::raw("sealed ").fg(MUTED),
                    Span::raw(digest).fg(BRIGHT).bold(),
                    Span::raw(format!("  {files} files  at {at}  receipt {seal_receipt}")).fg(MUTED),
                ]),
                Line::default(),
            ];
            body.push(if unchanged > 0 {
                Line::from(vec![
                    Span::raw("✓ ").fg(OK).bold(),
                    Span::raw(format!(
                        "unchanged since receipt {seal_receipt}: {unchanged} denied command{} checked it",
                        if unchanged == 1 { "" } else { "s" }
                    ))
                    .fg(TEXT),
                ])
            } else {
                Line::from("every agent command is checked against the seal").fg(MUTED)
            });
            if let Some((at, _)) = verified {
                body.push(Line::from(vec![
                    Span::raw("✓ ").fg(OK).bold(),
                    Span::raw(format!("verified at {at}: every file matches the seal")).fg(TEXT),
                ]));
            }
            body
        },
    );
    frame.render_widget(Paragraph::new(body).block(card(title, FOCUS)), area);
}

/// A stratum: name, root, whose it is and whether it runs commands.
struct Stratum {
    /// Name.
    name: &'static str,
    /// The root it runs on, or what it is for.
    root: &'static str,
    /// The agent that runs in it.
    role: Option<Role>,
    /// The walls, as declared.
    walls: &'static [&'static str],
}

/// Walls of an agent's stratum.
const AGENT_WALLS: &[&str] = &[
    "✕ network",
    "✕ capabilities",
    "✕ nested userns",
    "▣ evidence read-only",
    "✎ scratch writable",
];

/// Every stratum, exec first.
const STRATA: [Stratum; 4] = [
    Stratum {
        name: "hunter",
        root: "debian",
        role: Some(Role::Hunter),
        walls: AGENT_WALLS,
    },
    Stratum {
        name: "forensics",
        root: "alpine",
        role: Some(Role::Forensics),
        walls: AGENT_WALLS,
    },
    Stratum {
        name: "acme-fs",
        root: "debian · victim",
        role: None,
        walls: &["✕ network", "▣ root read-only", "✎ share read-write"],
    },
    Stratum {
        name: "rule-check",
        root: "yara rules",
        role: None,
        walls: &["✕ network", "✕ capabilities", "▣ rules read-only"],
    },
];

/// The strata as walled boxes, then the agents that run no commands.
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
    let probe = lines.iter().any(|(_, text)| text.contains("probe"));
    for (stratum, cell) in STRATA.iter().zip(cells.iter()) {
        render_stratum(frame, *cell, (state, now), stratum, (probe, lines));
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
            Span::raw("  model and bus only: it can ask, record and propose").fg(DIM),
        ]);
        frame.render_widget(Paragraph::new(body).block(card(title, LINE)), *cell);
    }
}

/// Commands run and denied in `stratum`, and whether a denial there is fresh.
fn counts(
    state: &State,
    stratum: &Stratum,
    lines: &[(&str, &str)],
    now: Timestamp,
) -> (usize, usize, bool) {
    let Some(role) = stratum.role else {
        let needle = if stratum.name == "acme-fs" {
            "detonated"
        } else {
            "rule-check"
        };
        let run = lines
            .iter()
            .filter(|(_, text)| text.contains(needle))
            .count();
        return (run, 0, false);
    };
    let mine = |activity: &&Activity| activity.who == Who::Agent(role);
    let run = state
        .activity
        .iter()
        .filter(mine)
        .filter(|activity| activity.tag == "TRACE" && activity.text.contains(" exec "))
        .count();
    let denied = state
        .denials
        .all()
        .iter()
        .filter(|denial| denial.role == Some(role))
        .count();
    let flashing = state.team.status(role, state.waiting_on(role), now) == Status::Blocked;
    (run, denied, flashing)
}

/// One stratum box: its walls, commands run and denied, red while a denial is fresh.
fn render_stratum(
    frame: &mut Frame<'_>,
    area: Rect,
    (state, now): (&State, Timestamp),
    stratum: &Stratum,
    (probe, lines): (bool, &[(&str, &str)]),
) {
    let (run, denied, flashing) = counts(state, stratum, lines, now);
    let border = if flashing { RED } else { LINE };
    let mut title = vec![Span::raw(" ")];
    if let Some(role) = stratum.role {
        title.push(Span::raw(format!("{} ", glyph(role))).fg(tint(role)));
    }
    title.push(Span::raw(stratum.name).fg(BRIGHT).bold());
    title.push(Span::raw(format!(" · {} ", stratum.root)).fg(MUTED));
    if flashing {
        title.push(Span::styled(
            " DENIED ",
            Style::new().fg(BRIGHT).bg(RED).bold(),
        ));
    }
    let width = usize::from(area.width.saturating_sub(4));
    let mut body: Vec<Line<'static>> = stratum
        .walls
        .iter()
        .map(|wall| {
            let (mark, rest) =
                wall.split_at(wall.char_indices().nth(1).map_or(0, |(index, _)| index));
            let verdict = if probe { "" } else { "declared" };
            Line::from(vec![
                Span::raw(mark.to_owned()).fg(ACCENT).bold(),
                Span::raw(pad(rest, width.saturating_sub(9))).fg(TEXT),
                Span::raw(verdict).fg(DIM),
            ])
        })
        .collect();
    body.push(Line::default());
    let unit = if stratum.role.is_some() {
        "commands"
    } else if stratum.name == "acme-fs" {
        "detonations"
    } else {
        "rule checks"
    };
    body.push(Line::from(vec![
        Span::raw(format!("{run:>3} ")).fg(BRIGHT).bold(),
        Span::raw(format!("{unit} run   ")).fg(MUTED),
        Span::raw(format!("{denied} "))
            .fg(if denied > 0 { RED } else { OK })
            .bold(),
        Span::raw("denied").fg(MUTED),
    ]));
    let total = run.max(1);
    let filled = (width.saturating_sub(2) * run.min(total))
        .checked_div(total)
        .unwrap_or(0);
    let red = (width.saturating_sub(2) * denied.min(total))
        .checked_div(total)
        .unwrap_or(0);
    body.push(Line::from(vec![
        Span::raw("▰".repeat(filled.saturating_sub(red))).fg(ACCENT),
        Span::raw("▰".repeat(red)).fg(RED),
        Span::raw("▱".repeat(width.saturating_sub(2).saturating_sub(filled))).fg(LINE),
    ]));
    frame.render_widget(
        Paragraph::new(body).block(card(Line::from(title), border)),
        area,
    );
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

/// The receipt chain: the newest receipts as linked blocks, and whether the chain verified.
fn render_chain(frame: &mut Frame<'_>, area: Rect, state: &State, lines: &[(&str, &str)]) {
    let mut receipts: Vec<(u64, &'static str)> = lines
        .iter()
        .filter(|(_, text)| !text.starts_with("evidence verified"))
        .filter_map(|(_, text)| receipt_in(text).map(|seq| (seq, receipt_kind(text))))
        .collect();
    receipts.sort_unstable();
    receipts.dedup_by_key(|(seq, _)| *seq);
    let verified = chain_verdict(state, lines);
    let title = Line::from(vec![
        Span::raw(" ◆ ").fg(ACCENT),
        Span::raw("receipt chain ").fg(BRIGHT).bold(),
    ]);
    let block = card(title, LINE)
        .title(Line::from(vec![Span::raw(" "), verified, Span::raw(" ")]).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width);
    let fits = (width + 3) / 13;
    let shown: Vec<(u64, &str)> = receipts
        .iter()
        .skip(receipts.len().saturating_sub(fits))
        .copied()
        .collect();
    if shown.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from("No receipts on the bus yet.").fg(DIM)),
            inner,
        );
        return;
    }
    let mut rows: [Vec<Span<'static>>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for (index, (seq, kind)) in shown.iter().enumerate() {
        let link = index > 0;
        let color = match *kind {
            "deny" | "reject" => RED,
            "tamper" => AMBER,
            "approve" | "admit" | "seal" => OK,
            _ => ACCENT,
        };
        let joins = [
            if link { "   " } else { "" },
            if link { "─◆─" } else { "" },
            if link { "   " } else { "" },
            if link { "   " } else { "" },
        ];
        for (row, join) in rows.iter_mut().zip(joins) {
            row.push(Span::raw(join).fg(ACCENT));
        }
        let [top, number, word, bottom] = &mut rows;
        top.push(Span::raw("╭────────╮").fg(LINE));
        number.push(Span::raw("│").fg(LINE));
        number.push(Span::styled(
            format!(" #{seq:<6} "),
            Style::new().fg(BRIGHT).bg(RAISED_HI).bold(),
        ));
        number.push(Span::raw("│").fg(LINE));
        word.push(Span::raw("│").fg(LINE));
        word.push(Span::raw(format!(" {kind:<7}")).fg(color));
        word.push(Span::raw("│").fg(LINE));
        bottom.push(Span::raw("╰────────╯").fg(LINE));
    }
    let chain: Vec<Line<'static>> = rows.into_iter().map(Line::from).collect();
    frame.render_widget(Paragraph::new(chain), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_give_root_states_receipts_and_kinds() {
        let lines = [
            (
                "15:19:01",
                "commander ab flipped byte 9 of layer sha256:dd in the staged copy of debian; the next admission checks it (receipt #5)",
            ),
            (
                "15:19:02",
                "root debian REJECTED: layer sha256:dd does not match its lock (receipt #6)",
            ),
            (
                "15:19:05",
                "root debian admitted: manifest sha256:c67e92c8, unpacked tree sha256:f1 (receipt #7)",
            ),
        ];
        assert_eq!(
            root_state("debian", lines.iter().copied()),
            RootState::Admitted {
                manifest: "sha256:c67e92c8".to_owned(),
                at: "15:19:05".to_owned()
            }
        );
        assert_eq!(
            root_state("alpine", lines.iter().copied()),
            RootState::Unknown
        );
        assert_eq!(
            root_state("debian", lines.iter().take(2).copied()),
            RootState::Rejected
        );
        let denied = "OS denied hunter: `sh -c rm -rf /evidence/*`: evidence is mounted read_only for hunter (receipt #45); evidence unchanged: still matches the seal from receipt #10";
        assert_eq!(
            receipt_in(denied),
            Some(45),
            "the first receipt, not the seal's"
        );
        assert_eq!(receipt_kind(denied), "deny");
        assert_eq!(receipt_kind(lines[0].1), "tamper");
    }
}
