//! Modal panels: the admission verdict, key help, the scenario picker, the reset confirmation and
//! access control.

use cleanroom_proto::Tri;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use tui_big_text::{BigText, PixelSize};

use super::{
    AccessForm, Field, Overlay, View, fit, flag_look, listed_members, pad, selected_member,
    tail_fit, width_of,
};
use crate::access::{Enrollment, MEMBER_ROLES, Standing, role_word};
use crate::state::{Admission, State, Tone, short_key};
use crate::theme::{
    ACCENT, ACCENT_BG, AMBER, BRIGHT, DIM, INK, MUTED, Name, OK, RAISED, RAISED_HI, RED, RED_BG,
    TEXT, scrim,
};

/// Width of the "REJECTED"/"ADMITTED" headline at half-height pixels.
const BIG_TEXT_WIDTH: u16 = 64;

/// The open modal, if any, over a faded screen. An undismissed admission result wins over
/// everything.
pub(super) fn render(frame: &mut Frame<'_>, area: Rect, state: &State, view: &View) {
    if view.admission_visible(state)
        && let Some(admission) = &state.admission
    {
        scrim(frame.buffer_mut(), view.palette());
        render_admission(frame, area, admission);
        return;
    }
    if view.overlay != Overlay::None {
        scrim(frame.buffer_mut(), view.palette());
    }
    match view.overlay {
        Overlay::None => {}
        Overlay::Help => render_help(frame, area),
        Overlay::Detonate { cursor } => render_detonate(frame, area, &view.scenarios, cursor),
        Overlay::ConfirmReset => render_confirm_reset(frame, area),
        Overlay::Members => render_members(frame, area, state, &view.access),
    }
}

/// The tamper beat: a big red refusal naming the layer and both digests, then a big admission
/// in the accent naming the manifest once the clean copy passes.
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
            Style::new().fg(BRIGHT).bg(RED_BG),
            vec![
                detail("Root", root.clone(), Style::new().bold()),
                detail("Layer", layer.clone(), Style::new().bold()),
                detail("Expected", expected.clone(), Style::new()),
                detail(
                    "Actual",
                    actual.clone(),
                    Style::new().fg(INK).bg(AMBER).bold(),
                ),
                Line::default(),
                Line::from("One byte changed, so the digest changed. The tampered root never ran.")
                    .bold(),
            ],
        ),
        Admission::Admitted { root, manifest } => (
            "ADMITTED",
            " ADMISSION OK · clean root admitted ",
            Style::new().fg(BRIGHT).bg(ACCENT_BG),
            vec![
                detail("Root", root.clone(), Style::new().bold()),
                detail(
                    "Manifest",
                    manifest.clone(),
                    Style::new().fg(ACCENT).bg(INK).bold(),
                ),
                Line::default(),
                Line::from("Every layer matches its signed lock. Strata launch from this root.")
                    .bold(),
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

/// A centered modal of `width` columns with `title` and `lines`; returns its inner area.
fn modal(
    frame: &mut Frame<'_>,
    area: Rect,
    (title, color): (&str, Color),
    width: u16,
    lines: Vec<Line<'static>>,
) -> Rect {
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let popup = area.centered(Constraint::Max(width), Constraint::Length(height));
    frame.render_widget(Clear, popup);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .style(Style::new().bg(RAISED).fg(TEXT))
        .title(Line::from(format!(" {title} ")).bold().fg(color));
    let inner = block.inner(popup);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        popup,
    );
    inner
}

/// Key reference.
fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let keys = [
        (
            "F1-F7 F10",
            "Overview, Lead, Scope, Record, Defense, Team, Memory; F10 the Controlroom (Tab cycles)",
        ),
        (
            "[ ]  ← →",
            "Move the focus between panels; the key bar shows the focused panel's keys",
        ),
        (", .", "Switch the Overview chart: Activity, Exec, Safety"),
        (
            "Enter",
            "Clean tab: send to Clean, the lead agent (@hunter, @forensics, @scribe, @containment asks one)",
        ),
        (
            "Esc",
            "Leave the message line for command keys; Enter or c returns",
        ),
        (
            "d",
            "Detonate a scenario in the sacrificial stratum (asks which)",
        ),
        (
            "t",
            "Tamper demo: flip a byte in a root, then try to admit it",
        ),
        (
            "A",
            "Shift+A: admit the root again; after a rejection the clean copy passes",
        ),
        (
            "a / x",
            "Approve / deny the selected item, signed with your key",
        ),
        (
            "↑ ↓",
            "Select an approval; in the Controlroom trace, a step (←→ switch panes)",
        ),
        ("g", "Toggle agent guardrails (hardened or naive prompts)"),
        ("i", "Start the agent team on the incident"),
        ("v", "Verify the receipt log's hash chain"),
        ("r", "Reset the demo (asks first)"),
        ("m", "Access control: members, enroll, revoke"),
        ("T", "Cycle the theme (saved for next time)"),
        (
            "PgUp PgDn",
            "Scroll the conversation; End returns to the newest",
        ),
        ("?  q", "This help · quit (Ctrl+C quits from anywhere)"),
    ];
    let mut lines: Vec<Line<'static>> = keys
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::raw(format!(" {key:<11}")).fg(ACCENT).bold(),
                Span::raw(*what).fg(TEXT),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::raw(" Colors  ").fg(MUTED),
        Span::styled(" YES ", flag_look(Tri::Yes).1),
        Span::raw(" breach or block  ").fg(MUTED),
        Span::styled(" ? ", flag_look(Tri::Unknown).1),
        Span::raw(" unknown or waiting  ").fg(MUTED),
        Span::styled(" no ", flag_look(Tri::No).1),
        Span::raw(" clean").fg(MUTED),
    ]));
    lines.push(Line::from(vec![
        Span::raw(" Themes  ").fg(MUTED),
        Span::raw(Name::listed()).fg(TEXT),
        Span::raw("  (T cycles; --theme NAME picks one)").fg(DIM),
    ]));
    lines.push(Line::from(" Esc or ? closes this help.").fg(DIM));
    modal(frame, area, ("KEYS", ACCENT), 96, lines);
}

/// Scenario picker for `d`.
fn render_detonate(frame: &mut Frame<'_>, area: Rect, scenarios: &[String], cursor: usize) {
    let mut lines: Vec<Line<'static>> = scenarios
        .iter()
        .enumerate()
        .map(|(index, name)| {
            if index == cursor {
                Line::from(format!(" ▸ {name} "))
                    .fg(BRIGHT)
                    .bg(RAISED_HI)
                    .bold()
            } else {
                Line::from(format!("   {name}")).fg(MUTED)
            }
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(
        " Runs inside the acme-fs stratum: no network, nothing leaves the sandbox.",
    ));
    lines.push(Line::from(" ↑↓ choose · Enter detonates · Esc cancels").fg(DIM));
    modal(frame, area, ("DETONATE WHICH SCENARIO?", AMBER), 84, lines);
}

/// Confirmation for `r`.
fn render_confirm_reset(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(" Reset the demo? cleanroomd re-seeds the victim and this console clears."),
        Line::default(),
        Line::from(" y resets · n or Esc cancels").fg(DIM),
    ];
    modal(frame, area, ("RESET", RED), 84, lines);
}

/// Access control: this console's key, the members this session knows, the enroll form and the
/// revoke prompt, with cleanroomd's latest answer.
fn render_members(frame: &mut Frame<'_>, area: Rect, state: &State, form: &AccessForm) {
    let width = 100.min(area.width.saturating_sub(4));
    let inner_width = usize::from(width.saturating_sub(4));
    let me = state.me.as_deref().unwrap_or("replay: no key");
    let mut lines = vec![
        Line::default(),
        Line::from(vec![
            Span::raw("  This console   ").fg(MUTED),
            Span::raw(fit(me, inner_width.saturating_sub(17))).fg(BRIGHT),
        ]),
        Line::from(fit(
            "  cleanroomd has no list operation, so this shows what this session saw on the bus.",
            inner_width,
        ))
        .fg(DIM),
        Line::default(),
        section("MEMBERS", form.field == Field::List),
    ];
    lines.extend(member_rows(state, form, inner_width));
    lines.extend([
        Line::default(),
        section("ENROLL A MEMBER", form.field != Field::List),
        field_line(
            "Public key",
            &form.key,
            form.field == Field::Key,
            inner_width,
        ),
        Line::default(),
        field_line("Name", &form.name, form.field == Field::Name, inner_width),
        Line::default(),
        role_line(form),
        Line::default(),
        status_line(state, form, inner_width),
        hints_line(form),
    ]);
    let inner = modal(frame, area, ("ACCESS CONTROL", ACCENT), width, lines);
    place_cursor(frame, inner, state, form);
}

/// Rows above the public-key field: blank, this console, the note, blank, the heading, the
/// member rows, blank and the form heading.
fn form_row(state: &State) -> usize {
    5 + member_rows_len(state) + 2
}

/// A section heading in the overlay, lit when it has focus.
fn section(text: &str, focused: bool) -> Line<'static> {
    let color = if focused { ACCENT } else { MUTED };
    Line::from(Span::raw(format!("  {text}")).fg(color).bold())
}

/// This console, then every other member this session knows about.
fn member_rows(state: &State, form: &AccessForm, width: usize) -> Vec<Line<'static>> {
    let me = state.me.as_deref();
    let mine = me.and_then(|key| state.roster.get(key));
    let mut rows = vec![member_row(
        form.selected == 0,
        form,
        ("you", mine),
        me.unwrap_or(""),
        width,
    )];
    let others = listed_members(state);
    if others.is_empty() && mine.is_none() {
        rows.push(
            Line::from(fit(
                "    nobody enrolled or revoked yet this session; until someone is enrolled, any local key approves",
                width,
            ))
            .fg(DIM),
        );
    }
    for (index, member) in others.into_iter().enumerate() {
        rows.push(member_row(
            form.selected == index + 1,
            form,
            ("", Some(member)),
            &member.key_id,
            width,
        ));
    }
    rows
}

/// How many rows the member list takes.
fn member_rows_len(state: &State) -> usize {
    let mine = state.me.as_deref().and_then(|key| state.roster.get(key));
    let others = listed_members(state).len();
    1 + others + usize::from(others == 0 && mine.is_none())
}

/// One member row: name, role, key and standing.
fn member_row(
    selected: bool,
    form: &AccessForm,
    (label, member): (&str, Option<&Enrollment>),
    key_id: &str,
    width: usize,
) -> Line<'static> {
    let selected = selected && form.field == Field::List;
    let base = if selected {
        Style::new().bg(RAISED_HI)
    } else {
        Style::new()
    };
    let name = match (
        member.and_then(|member| member.name.clone()),
        label.is_empty(),
    ) {
        (Some(name), true) => name,
        (Some(name), false) => format!("{name} ({label})"),
        (None, _) => label.to_owned(),
    };
    let role = member.and_then(|member| member.role).map_or("—", role_word);
    let (standing, color) = match member.map(|member| member.standing) {
        Some(Standing::Enrolled) => ("enrolled", ACCENT),
        Some(Standing::Revoked) => ("revoked", RED),
        None => ("no enrollment seen this session", DIM),
    };
    let receipt = member
        .and_then(|member| member.receipt)
        .map(|seq| format!(" · receipt #{seq}"))
        .unwrap_or_default();
    let key = if key_id.is_empty() {
        String::new()
    } else {
        format!("sha256:{}…", short_key(key_id))
    };
    let used = 4 + 24 + 12 + 20;
    Line::from(vec![
        Span::styled(
            if selected { "  ▸ " } else { "    " },
            base.fg(ACCENT).bold(),
        ),
        Span::styled(pad(&name, 24), base.fg(BRIGHT).bold()),
        Span::styled(pad(role, 12), base.fg(MUTED)),
        Span::styled(pad(&key, 20), base.fg(DIM)),
        Span::styled(
            fit(&format!("{standing}{receipt}"), width.saturating_sub(used)),
            base.fg(color),
        ),
    ])
}

/// The width of a text box in the form.
fn box_width(width: usize) -> usize {
    width.saturating_sub(18).min(68)
}

/// `Public key   [ 0f3a…               ]`.
fn field_line(label: &str, value: &str, focused: bool, width: usize) -> Line<'static> {
    let room = box_width(width);
    let shown = tail_fit(value, room.saturating_sub(2));
    let style = if focused {
        Style::new().fg(BRIGHT).bg(RAISED_HI)
    } else {
        Style::new().fg(TEXT).bg(INK)
    };
    Line::from(vec![
        Span::raw(format!("    {label:<12}")).fg(if focused { ACCENT } else { MUTED }),
        Span::styled(format!(" {}", pad(&shown, room.saturating_sub(1))), style),
    ])
}

/// `Role         admin  commander  responder  observer`, the chosen one lit.
fn role_line(form: &AccessForm) -> Line<'static> {
    let focused = form.field == Field::Role;
    let mut spans = vec![Span::raw("    Role        ").fg(if focused { ACCENT } else { MUTED })];
    for role in MEMBER_ROLES {
        let word = role_word(role);
        if role == form.role {
            let style = if focused {
                Style::new().fg(BRIGHT).bg(ACCENT_BG).bold()
            } else {
                Style::new().fg(BRIGHT).bg(RAISED_HI).bold()
            };
            spans.push(Span::styled(format!(" {word} "), style));
        } else {
            spans.push(Span::raw(format!(" {word} ")).fg(DIM));
        }
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

/// The revoke prompt's lead-in: `  Revoke Ada? Reason: `.
fn revoke_prompt(state: &State, form: &AccessForm) -> String {
    let who = selected_member(state, form).map_or_else(
        || "this member".to_owned(),
        |member| {
            member
                .name
                .clone()
                .unwrap_or_else(|| format!("sha256:{}…", short_key(&member.key_id)))
        },
    );
    format!("  Revoke {who}? Reason: ")
}

/// cleanroomd's latest answer, or the revoke prompt while it is open.
fn status_line(state: &State, form: &AccessForm, width: usize) -> Line<'static> {
    if let Some(reason) = &form.reason {
        let prompt = revoke_prompt(state, form);
        let room = width.saturating_sub(width_of(&prompt) + 2);
        return Line::from(vec![
            Span::raw(prompt).fg(RED).bold(),
            Span::styled(
                format!(
                    " {} ",
                    pad(
                        &tail_fit(reason, room.saturating_sub(1)),
                        room.saturating_sub(1)
                    )
                ),
                Style::new().fg(BRIGHT).bg(RAISED_HI),
            ),
        ]);
    }
    state.notice.as_ref().map_or_else(
        || Line::from("  cleanroomd answers here.").fg(DIM),
        |notice| {
            let (mark, color) = match notice.tone {
                Tone::Bad => ("✕ ", RED),
                Tone::Good => ("✓ ", OK),
                Tone::Warn => ("! ", AMBER),
                Tone::Quiet | Tone::Plain => ("· ", MUTED),
            };
            Line::from(vec![
                Span::raw(format!("  {mark}")).fg(color).bold(),
                Span::raw(fit(&notice.text, width.saturating_sub(4))).fg(color),
            ])
        },
    )
}

/// Keys for the focused part.
fn hints_line(form: &AccessForm) -> Line<'static> {
    let text = match (form.reason.is_some(), form.field) {
        (true, _) => "  Enter revokes, signed with your key · Esc cancels",
        (false, Field::List) => {
            "  ↑↓ select · Enter copies into the form · r revokes · Tab to the form · Esc closes"
        }
        (false, Field::Key | Field::Name) => {
            "  Type or paste · Tab next field · Enter enrolls, signed with your key · Esc closes"
        }
        (false, Field::Role) => "  ←→ choose a role · Tab next · Enter enrolls · Esc closes",
    };
    Line::from(text).fg(DIM)
}

/// Put the terminal cursor at the end of the focused text field.
fn place_cursor(frame: &mut Frame<'_>, inner: Rect, state: &State, form: &AccessForm) {
    let width = usize::from(inner.width);
    let first = form_row(state);
    let (row, column) = match (form.reason.as_ref(), form.field) {
        (Some(reason), _) => {
            let prompt = revoke_prompt(state, form);
            let room = width
                .saturating_sub(width_of(&prompt) + 2)
                .saturating_sub(1);
            (
                first + 6,
                width_of(&prompt) + 1 + width_of(&tail_fit(reason, room)),
            )
        }
        (None, Field::Key) => (
            first,
            17 + width_of(&tail_fit(&form.key, box_width(width).saturating_sub(2))),
        ),
        (None, Field::Name) => (
            first + 2,
            17 + width_of(&tail_fit(&form.name, box_width(width).saturating_sub(2))),
        ),
        (None, Field::List | Field::Role) => return,
    };
    let x = inner
        .x
        .saturating_add(u16::try_from(column).unwrap_or(u16::MAX));
    let y = inner
        .y
        .saturating_add(u16::try_from(row).unwrap_or(u16::MAX));
    if y < inner.bottom() {
        frame.set_cursor_position(Position::new(x.min(inner.right().saturating_sub(1)), y));
    }
}
