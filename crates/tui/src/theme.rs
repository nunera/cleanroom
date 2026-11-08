//! Themes: named palettes over one set of semantic colors.
//!
//! Every theme gives the same roles a color: surfaces and chrome, one accent (healthy, live, the
//! brand), the focus border, "ok", red only for a breach or a block, amber only for something
//! unknown or waiting, a tint per agent role, the clean sky of the banner and the memory map's
//! layer and source colors. The breach and waiting skies are shared, so red and amber mean the
//! same thing in every theme.
//!
//! Screens draw with the semantic constants below ([`INK`], [`ACCENT`], …). They are palette
//! slots, not colors: [`Theme::resolve`] turns them into the active theme's 24-bit colors once
//! the frame is drawn. Code that needs real colors (blends, tweens, effects) asks the active
//! [`Theme`] for them. With `NO_COLOR` set, [`strip`] removes every color instead and reverses
//! cells that sat on a signal background, so badges and banners still stand out.

use std::env;

use cleanroom_proto::Role;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding};

/// First terminal color index used as a palette slot.
const SLOT_BASE: u8 = 200;

/// Palette slot `index`, resolved by the active theme when the frame is done.
const fn slot(index: u8) -> Color {
    Color::Indexed(SLOT_BASE + index)
}

/// Background of every screen.
pub(crate) const INK: Color = slot(0);
/// Raised surfaces: the top bar, cards, the input line.
pub(crate) const RAISED: Color = slot(1);
/// A surface one step higher: selected rows, the commander's messages, keycaps.
pub(crate) const RAISED_HI: Color = slot(2);
/// Borders, rules and idle connectors.
pub(crate) const LINE: Color = slot(3);
/// Quiet text: timestamps, markers, placeholders.
pub(crate) const DIM: Color = slot(4);
/// Secondary text and labels.
pub(crate) const MUTED: Color = slot(5);
/// Body text.
pub(crate) const TEXT: Color = slot(6);
/// Headings and names.
pub(crate) const BRIGHT: Color = slot(7);
/// The one accent: live, the brand, links and keys.
pub(crate) const ACCENT: Color = slot(8);
/// The accent as a surface (the active tab, a table header).
pub(crate) const ACCENT_BG: Color = slot(9);
/// The focused panel's border.
pub(crate) const FOCUS: Color = slot(10);
/// Healthy: clean, intact, safe, not exposed.
pub(crate) const OK: Color = slot(11);
/// The thin rule under the tab bar.
pub(crate) const RULE: Color = slot(12);
/// A breach or a block, as text.
pub(crate) const RED: Color = slot(13);
/// A breach or a block, as a surface (the kernel banner, a compromised tile).
pub(crate) const RED_BG: Color = slot(14);
/// Unknown or waiting, as text.
pub(crate) const AMBER: Color = slot(15);
/// Unknown or waiting, as a surface.
pub(crate) const AMBER_BG: Color = slot(16);
/// Slots 17 to 21: the role tints, in the order of [`Theme::roles`].
const ROLE_SLOT: u8 = 17;
/// Number of slots.
const SLOTS: usize = 22;

/// How much of the alarm color tints each banner row, top to horizon (out of 256): a hint that
/// gathers at the horizon, so the sky stays the theme's own.
const ALARM_HINT: [u16; 6] = [0, 6, 12, 22, 36, 56];

/// Glyph that stands for a role everywhere on screen.
pub(crate) const fn glyph(role: Role) -> &'static str {
    match role {
        Role::Lead => "◆",
        Role::Hunter => "▲",
        Role::Forensics => "●",
        Role::Scribe => "■",
        Role::Containment => "▣",
    }
}

/// A role's tint: low saturation, so it never competes with red, amber or the accent. The Lead
/// wears the accent because it is the commander's point of contact.
pub(crate) const fn tint(role: Role) -> Color {
    match role {
        Role::Lead => slot(ROLE_SLOT),
        Role::Hunter => slot(ROLE_SLOT + 1),
        Role::Forensics => slot(ROLE_SLOT + 2),
        Role::Scribe => slot(ROLE_SLOT + 3),
        Role::Containment => slot(ROLE_SLOT + 4),
    }
}

/// A theme's name, as typed after `--theme` and saved between sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Name {
    /// Sterile teal on deep ink: the operating theatre.
    #[default]
    Cleanroom,
    /// Orange on warm near-black under a sunset.
    Ember,
    /// Lavender with orange focus on slate.
    Lavender,
    /// Green CRT on black.
    Phosphor,
    /// High contrast for a washed-out projector.
    Projector,
}

impl Name {
    /// Every theme, in the order `T` cycles them.
    pub(crate) const ALL: [Self; 5] = [
        Self::Cleanroom,
        Self::Ember,
        Self::Lavender,
        Self::Phosphor,
        Self::Projector,
    ];

    /// The name as typed and shown.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Cleanroom => "cleanroom",
            Self::Ember => "ember",
            Self::Lavender => "lavender",
            Self::Phosphor => "phosphor",
            Self::Projector => "projector",
        }
    }

    /// The theme called `text` (any case, surrounding space ignored).
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        Self::ALL
            .into_iter()
            .find(|name| name.label().eq_ignore_ascii_case(text))
    }

    /// The theme after this one, wrapping around.
    pub(crate) fn next(self) -> Self {
        let index = Self::ALL.iter().position(|name| *name == self).unwrap_or(0);
        Self::ALL
            .get((index + 1) % Self::ALL.len())
            .copied()
            .unwrap_or_default()
    }

    /// Every name, comma-separated, for help and errors.
    pub(crate) fn listed() -> String {
        Self::ALL.map(Self::label).join(", ")
    }

    /// The palette.
    pub(crate) const fn theme(self) -> &'static Theme {
        match self {
            Self::Cleanroom => &CLEANROOM,
            Self::Ember => &EMBER,
            Self::Lavender => &LAVENDER,
            Self::Phosphor => &PHOSPHOR,
            Self::Projector => &PROJECTOR,
        }
    }
}

/// One palette: a 24-bit color for every semantic role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Theme {
    /// Background.
    pub(crate) ink: Color,
    /// Raised surfaces.
    pub(crate) raised: Color,
    /// Selected rows and keycaps.
    pub(crate) raised_hi: Color,
    /// Borders and rules.
    pub(crate) line: Color,
    /// Quiet text.
    pub(crate) dim: Color,
    /// Secondary text.
    pub(crate) muted: Color,
    /// Body text.
    pub(crate) text: Color,
    /// Headings and names.
    pub(crate) bright: Color,
    /// The accent.
    pub(crate) accent: Color,
    /// The accent as a surface.
    pub(crate) accent_bg: Color,
    /// The focused panel's border.
    pub(crate) focus: Color,
    /// Healthy.
    pub(crate) ok: Color,
    /// The rule under the tab bar.
    pub(crate) rule: Color,
    /// Breach or block.
    pub(crate) red: Color,
    /// Breach or block, as a surface.
    pub(crate) red_bg: Color,
    /// Unknown or waiting.
    pub(crate) amber: Color,
    /// Unknown or waiting, as a surface.
    pub(crate) amber_bg: Color,
    /// Role tints: Lead, Hunter, Forensics, Scribe, Containment.
    pub(crate) roles: [Color; 5],
    /// The banner's clean sky, top row to horizon.
    pub(crate) sky: [Color; 6],
    /// Memory map: Mamba-2 layers, as text.
    pub(crate) mamba: Color,
    /// Memory map: Mamba-2 layers, as a surface.
    pub(crate) mamba_bg: Color,
    /// Memory map: mixture-of-experts layers, as text.
    pub(crate) expert: Color,
    /// Memory map: mixture-of-experts layers, as a surface.
    pub(crate) expert_bg: Color,
    /// Memory map: spans the commander wrote.
    pub(crate) commander: Color,
    /// Memory map: the agent's own spans.
    pub(crate) agent: Color,
    /// Memory map: trusted tool output.
    pub(crate) tool: Color,
}

impl Theme {
    /// The color slot `color` stands for in this theme; real colors pass through.
    pub(crate) fn rgb(&self, color: Color) -> Color {
        lookup(&self.slots(), color)
    }

    /// The banner's sky under an alarm of `color` (red for a breach, amber while waiting): this
    /// theme's clean sky with a hint of the alarm toward the horizon.
    pub(crate) fn alarm_sky(&self, color: Color) -> [Color; 6] {
        let alarm = self.rgb(color);
        let mut sky = self.sky;
        for (row, amount) in sky.iter_mut().zip(ALARM_HINT) {
            *row = blend(*row, alarm, amount);
        }
        sky
    }

    /// Every slot's color, by slot number.
    fn slots(&self) -> [Color; SLOTS] {
        let [lead, hunter, forensics, scribe, containment] = self.roles;
        [
            self.ink,
            self.raised,
            self.raised_hi,
            self.line,
            self.dim,
            self.muted,
            self.text,
            self.bright,
            self.accent,
            self.accent_bg,
            self.focus,
            self.ok,
            self.rule,
            self.red,
            self.red_bg,
            self.amber,
            self.amber_bg,
            lead,
            hunter,
            forensics,
            scribe,
            containment,
        ]
    }

    /// Turn every palette slot drawn into `buffer` into this theme's color.
    pub(crate) fn resolve(&self, buffer: &mut Buffer) {
        let slots = self.slots();
        for cell in &mut buffer.content {
            cell.fg = lookup(&slots, cell.fg);
            cell.bg = lookup(&slots, cell.bg);
            cell.underline_color = lookup(&slots, cell.underline_color);
        }
    }

    /// A rounded panel with `title` inset in its top border. The focused panel's border and title
    /// are the focus color; the others stay quiet.
    pub(crate) fn panel(&self, title: &str, focused: bool) -> Block<'static> {
        let (border, title_color) = if focused {
            (self.focus, self.focus)
        } else {
            (self.line, self.muted)
        };
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border))
            .title(Line::from(vec![
                Span::raw(" "),
                Span::raw(title.to_owned()).fg(title_color).bold(),
                Span::raw(" "),
            ]))
            .padding(Padding::horizontal(1))
    }
}

/// The color `slots` give the palette slot `color`; real colors pass through.
fn lookup(slots: &[Color; SLOTS], color: Color) -> Color {
    if let Color::Indexed(index) = color
        && let Some(slot) = index.checked_sub(SLOT_BASE)
        && let Some(resolved) = slots.get(usize::from(slot))
    {
        *resolved
    } else {
        color
    }
}

/// Sterile teal on deep ink.
const CLEANROOM: Theme = Theme {
    ink: Color::Rgb(10, 14, 19),
    raised: Color::Rgb(19, 25, 33),
    raised_hi: Color::Rgb(30, 39, 50),
    line: Color::Rgb(46, 57, 70),
    dim: Color::Rgb(104, 117, 132),
    muted: Color::Rgb(146, 158, 172),
    text: Color::Rgb(214, 222, 230),
    bright: Color::Rgb(242, 246, 249),
    accent: Color::Rgb(54, 214, 196),
    accent_bg: Color::Rgb(14, 74, 70),
    focus: Color::Rgb(54, 214, 196),
    ok: Color::Rgb(54, 214, 196),
    rule: Color::Rgb(24, 92, 86),
    red: Color::Rgb(246, 88, 88),
    red_bg: Color::Rgb(150, 26, 36),
    amber: Color::Rgb(242, 180, 66),
    amber_bg: Color::Rgb(104, 72, 16),
    roles: [
        Color::Rgb(54, 214, 196),
        Color::Rgb(150, 178, 204),
        Color::Rgb(178, 166, 206),
        Color::Rgb(204, 188, 160),
        Color::Rgb(164, 196, 180),
    ],
    sky: [
        Color::Rgb(9, 17, 26),
        Color::Rgb(10, 28, 38),
        Color::Rgb(12, 42, 50),
        Color::Rgb(14, 60, 64),
        Color::Rgb(20, 84, 82),
        Color::Rgb(30, 112, 104),
    ],
    mamba: Color::Rgb(132, 172, 222),
    mamba_bg: Color::Rgb(26, 50, 80),
    expert: Color::Rgb(180, 158, 226),
    expert_bg: Color::Rgb(50, 38, 78),
    commander: Color::Rgb(216, 198, 156),
    agent: Color::Rgb(146, 160, 182),
    tool: Color::Rgb(112, 178, 140),
};

/// Orange on warm near-black, red borders, a sunset sky; breach stays a hot red fill and waiting
/// a clear yellow, both apart from the orange accent.
const EMBER: Theme = Theme {
    ink: Color::Rgb(22, 15, 14),
    raised: Color::Rgb(36, 24, 22),
    raised_hi: Color::Rgb(58, 38, 34),
    line: Color::Rgb(116, 38, 32),
    dim: Color::Rgb(146, 126, 118),
    muted: Color::Rgb(182, 166, 156),
    text: Color::Rgb(238, 226, 216),
    bright: Color::Rgb(252, 246, 240),
    accent: Color::Rgb(255, 140, 58),
    accent_bg: Color::Rgb(122, 48, 22),
    focus: Color::Rgb(255, 140, 58),
    ok: Color::Rgb(156, 210, 104),
    rule: Color::Rgb(156, 32, 30),
    red: Color::Rgb(255, 60, 78),
    red_bg: Color::Rgb(200, 14, 42),
    amber: Color::Rgb(255, 216, 64),
    amber_bg: Color::Rgb(112, 88, 10),
    roles: [
        Color::Rgb(255, 140, 58),
        Color::Rgb(220, 178, 146),
        Color::Rgb(206, 166, 196),
        Color::Rgb(232, 206, 154),
        Color::Rgb(186, 206, 156),
    ],
    sky: [
        Color::Rgb(24, 14, 26),
        Color::Rgb(42, 18, 36),
        Color::Rgb(66, 24, 42),
        Color::Rgb(98, 34, 44),
        Color::Rgb(138, 54, 42),
        Color::Rgb(184, 86, 40),
    ],
    mamba: Color::Rgb(236, 176, 124),
    mamba_bg: Color::Rgb(74, 38, 24),
    expert: Color::Rgb(226, 156, 176),
    expert_bg: Color::Rgb(68, 28, 42),
    commander: Color::Rgb(240, 210, 152),
    agent: Color::Rgb(186, 166, 156),
    tool: Color::Rgb(156, 210, 104),
};

/// Lavender accent with orange focus on slate.
const LAVENDER: Theme = Theme {
    ink: Color::Rgb(30, 32, 46),
    raised: Color::Rgb(40, 43, 61),
    raised_hi: Color::Rgb(56, 60, 84),
    line: Color::Rgb(86, 90, 122),
    dim: Color::Rgb(122, 126, 158),
    muted: Color::Rgb(160, 164, 194),
    text: Color::Rgb(212, 215, 234),
    bright: Color::Rgb(244, 244, 252),
    accent: Color::Rgb(190, 158, 248),
    accent_bg: Color::Rgb(76, 60, 122),
    focus: Color::Rgb(255, 160, 92),
    ok: Color::Rgb(132, 216, 172),
    rule: Color::Rgb(112, 92, 172),
    red: Color::Rgb(255, 112, 120),
    red_bg: Color::Rgb(170, 36, 62),
    amber: Color::Rgb(246, 198, 92),
    amber_bg: Color::Rgb(106, 82, 26),
    roles: [
        Color::Rgb(190, 158, 248),
        Color::Rgb(142, 182, 232),
        Color::Rgb(232, 152, 202),
        Color::Rgb(242, 192, 142),
        Color::Rgb(152, 212, 192),
    ],
    sky: [
        Color::Rgb(22, 22, 36),
        Color::Rgb(30, 29, 52),
        Color::Rgb(42, 38, 70),
        Color::Rgb(58, 50, 94),
        Color::Rgb(78, 64, 122),
        Color::Rgb(104, 82, 154),
    ],
    mamba: Color::Rgb(142, 182, 242),
    mamba_bg: Color::Rgb(40, 52, 92),
    expert: Color::Rgb(212, 172, 250),
    expert_bg: Color::Rgb(68, 50, 102),
    commander: Color::Rgb(242, 202, 152),
    agent: Color::Rgb(162, 168, 198),
    tool: Color::Rgb(132, 216, 172),
};

/// Green CRT phosphor on black.
const PHOSPHOR: Theme = Theme {
    ink: Color::Rgb(2, 8, 4),
    raised: Color::Rgb(6, 20, 10),
    raised_hi: Color::Rgb(12, 36, 18),
    line: Color::Rgb(24, 88, 42),
    dim: Color::Rgb(50, 146, 74),
    muted: Color::Rgb(82, 188, 108),
    text: Color::Rgb(140, 242, 160),
    bright: Color::Rgb(204, 255, 214),
    accent: Color::Rgb(72, 255, 132),
    accent_bg: Color::Rgb(12, 72, 32),
    focus: Color::Rgb(72, 255, 132),
    ok: Color::Rgb(72, 255, 132),
    rule: Color::Rgb(26, 112, 52),
    red: Color::Rgb(255, 86, 86),
    red_bg: Color::Rgb(164, 20, 24),
    amber: Color::Rgb(255, 208, 64),
    amber_bg: Color::Rgb(102, 78, 12),
    roles: [
        Color::Rgb(72, 255, 132),
        Color::Rgb(122, 222, 172),
        Color::Rgb(172, 242, 122),
        Color::Rgb(212, 242, 152),
        Color::Rgb(102, 212, 202),
    ],
    sky: [
        Color::Rgb(2, 10, 4),
        Color::Rgb(4, 20, 8),
        Color::Rgb(6, 34, 14),
        Color::Rgb(10, 52, 22),
        Color::Rgb(16, 74, 32),
        Color::Rgb(26, 100, 46),
    ],
    mamba: Color::Rgb(122, 232, 202),
    mamba_bg: Color::Rgb(10, 52, 42),
    expert: Color::Rgb(192, 252, 142),
    expert_bg: Color::Rgb(38, 62, 14),
    commander: Color::Rgb(222, 252, 172),
    agent: Color::Rgb(112, 192, 132),
    tool: Color::Rgb(72, 255, 132),
};

/// High contrast for a washed-out projector: black ground, light borders, no faint greys.
const PROJECTOR: Theme = Theme {
    ink: Color::Rgb(0, 0, 0),
    raised: Color::Rgb(28, 30, 34),
    raised_hi: Color::Rgb(58, 62, 70),
    line: Color::Rgb(164, 170, 182),
    dim: Color::Rgb(196, 200, 208),
    muted: Color::Rgb(222, 226, 232),
    text: Color::Rgb(250, 250, 250),
    bright: Color::Rgb(255, 255, 255),
    accent: Color::Rgb(0, 230, 255),
    accent_bg: Color::Rgb(0, 92, 120),
    focus: Color::Rgb(0, 230, 255),
    ok: Color::Rgb(0, 240, 128),
    rule: Color::Rgb(0, 176, 206),
    red: Color::Rgb(255, 72, 72),
    red_bg: Color::Rgb(214, 0, 0),
    amber: Color::Rgb(255, 224, 0),
    amber_bg: Color::Rgb(142, 108, 0),
    roles: [
        Color::Rgb(0, 230, 255),
        Color::Rgb(132, 202, 255),
        Color::Rgb(232, 162, 255),
        Color::Rgb(255, 216, 152),
        Color::Rgb(142, 255, 202),
    ],
    sky: [
        Color::Rgb(0, 24, 36),
        Color::Rgb(0, 46, 64),
        Color::Rgb(0, 72, 96),
        Color::Rgb(0, 100, 128),
        Color::Rgb(0, 132, 162),
        Color::Rgb(0, 168, 200),
    ],
    mamba: Color::Rgb(152, 212, 255),
    mamba_bg: Color::Rgb(0, 62, 112),
    expert: Color::Rgb(232, 182, 255),
    expert_bg: Color::Rgb(82, 30, 122),
    commander: Color::Rgb(255, 226, 172),
    agent: Color::Rgb(212, 216, 226),
    tool: Color::Rgb(0, 240, 128),
};

/// How the console may use color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Colors {
    /// 24-bit color.
    Full,
    /// No color at all (`NO_COLOR`): emphasis and reversed badges only.
    Off,
}

impl Colors {
    /// `NO_COLOR` set to anything non-empty turns color off (<https://no-color.org>).
    pub(crate) fn from_env() -> Self {
        if env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
            Self::Off
        } else {
            Self::Full
        }
    }
}

/// Drop every color from `buffer`, keeping emphasis. Cells drawn on a signal surface (a red
/// banner, an amber or accent tile, a selected row) are reversed instead, so they still read.
pub(crate) fn strip(buffer: &mut Buffer) {
    for cell in &mut buffer.content {
        if matches!(cell.bg, RED_BG | AMBER_BG | ACCENT_BG | RAISED_HI) {
            cell.modifier.insert(Modifier::REVERSED);
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
        cell.underline_color = Color::Reset;
    }
}

/// Fade everything already drawn toward `theme`'s ink, so a modal drawn on top is the one thing
/// in focus.
pub(crate) fn scrim(buffer: &mut Buffer, theme: &Theme) {
    for cell in &mut buffer.content {
        cell.fg = blend(theme.rgb(cell.fg), theme.ink, 192);
        cell.bg = blend(theme.rgb(cell.bg), theme.ink, 192);
    }
}

/// `from` moved `amount`/256 of the way to `to` (RGB only; other colors stay `from`).
pub(crate) fn blend(from: Color, to: Color, amount: u16) -> Color {
    let (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) = (from, to) else {
        return from;
    };
    let amount = amount.min(256);
    let step = |a: u8, b: u8| {
        let value = (u16::from(a) * (256 - amount) + u16::from(b) * amount) / 256;
        u8::try_from(value).unwrap_or(u8::MAX)
    };
    Color::Rgb(step(r1, r2), step(g1, g2), step(b1, b2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_in_any_case_and_cycle_through_every_theme() {
        assert_eq!(Name::parse(" Ember\n"), Some(Name::Ember));
        assert_eq!(Name::parse("PROJECTOR"), Some(Name::Projector));
        assert_eq!(Name::parse("solarized"), None);
        let mut seen = vec![Name::default()];
        let mut name = Name::default();
        for _ in 1..Name::ALL.len() {
            name = name.next();
            seen.push(name);
        }
        assert_eq!(seen, Name::ALL);
        assert_eq!(name.next(), Name::Cleanroom, "wraps around");
    }

    #[test]
    fn slots_resolve_to_the_theme_and_real_colors_pass_through() {
        let theme = Name::Ember.theme();
        assert_eq!(theme.rgb(ACCENT), theme.accent);
        assert_eq!(theme.rgb(tint(Role::Scribe)), theme.roles[3]);
        assert_eq!(theme.rgb(Color::Rgb(1, 2, 3)), Color::Rgb(1, 2, 3));
        let mut buffer = Buffer::empty(ratatui::layout::Rect::new(0, 0, 2, 1));
        if let Some(cell) = buffer.cell_mut((0, 0)) {
            cell.set_fg(RED).set_bg(RED_BG);
        }
        theme.resolve(&mut buffer);
        let cell = buffer.cell((0, 0)).cloned().unwrap_or_default();
        assert_eq!((cell.fg, cell.bg), (theme.red, theme.red_bg));
    }
}
