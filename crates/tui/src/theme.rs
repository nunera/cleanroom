//! The palette of an operating theatre.
//!
//! Deep ink, one sterile teal accent for healthy state and the brand, red only for a breach or
//! a block, amber only for something unknown or waiting, and muted greys for chrome. Roles get a
//! subtle tint and a glyph, never a status color.
//!
//! Screens draw in 24-bit color. With `NO_COLOR` set, [`strip`] removes every color after drawing
//! and reverses cells that sat on a signal background, so badges and banners still stand out.

use std::env;

use cleanroom_proto::Role;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding};

/// Background of every screen.
pub(crate) const INK: Color = Color::Rgb(10, 14, 19);
/// Raised surfaces: the top bar, cards, the input line.
pub(crate) const RAISED: Color = Color::Rgb(19, 25, 33);
/// A surface one step higher: selected rows, the commander's messages, keycaps.
pub(crate) const RAISED_HI: Color = Color::Rgb(30, 39, 50);
/// Borders, rules and idle connectors.
pub(crate) const LINE: Color = Color::Rgb(46, 57, 70);
/// Quiet text: timestamps, markers, placeholders.
pub(crate) const DIM: Color = Color::Rgb(104, 117, 132);
/// Secondary text and labels.
pub(crate) const MUTED: Color = Color::Rgb(146, 158, 172);
/// Body text.
pub(crate) const TEXT: Color = Color::Rgb(214, 222, 230);
/// Headings and names.
pub(crate) const BRIGHT: Color = Color::Rgb(242, 246, 249);
/// The one accent: healthy, clean, live, and the brand.
pub(crate) const ACCENT: Color = Color::Rgb(54, 214, 196);
/// The accent as a surface (a clean asset tile, the active tab).
pub(crate) const ACCENT_BG: Color = Color::Rgb(14, 74, 70);
/// A breach or a block, as text.
pub(crate) const RED: Color = Color::Rgb(246, 88, 88);
/// A breach or a block, as a surface (the kernel banner, a compromised tile).
pub(crate) const RED_BG: Color = Color::Rgb(150, 26, 36);
/// Unknown or waiting, as text.
pub(crate) const AMBER: Color = Color::Rgb(242, 180, 66);
/// Unknown or waiting, as a surface.
pub(crate) const AMBER_BG: Color = Color::Rgb(104, 72, 16);

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
        Role::Lead => ACCENT,
        Role::Hunter => Color::Rgb(150, 178, 204),
        Role::Forensics => Color::Rgb(178, 166, 206),
        Role::Scribe => Color::Rgb(204, 188, 160),
        Role::Containment => Color::Rgb(164, 196, 180),
    }
}

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

/// Fade everything already drawn toward the ink, so a modal drawn on top is the one thing in
/// focus.
pub(crate) fn scrim(buffer: &mut Buffer) {
    for cell in &mut buffer.content {
        cell.fg = fade(cell.fg);
        cell.bg = fade(cell.bg);
    }
}

/// `color` a quarter of the way from the ink to itself.
fn fade(color: Color) -> Color {
    let Color::Rgb(red, green, blue) = color else {
        return color;
    };
    let Color::Rgb(ink_red, ink_green, ink_blue) = INK else {
        return color;
    };
    let mix = |channel: u8, ink: u8| {
        let faded = i32::from(ink) + (i32::from(channel) - i32::from(ink)) / 4;
        u8::try_from(faded.clamp(0, 255)).unwrap_or(ink)
    };
    Color::Rgb(
        mix(red, ink_red),
        mix(green, ink_green),
        mix(blue, ink_blue),
    )
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

/// The palette as a value, for renderers that take it as a parameter.
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
    /// Breach or block.
    pub(crate) red: Color,
    /// Breach or block, as a surface.
    pub(crate) red_bg: Color,
    /// Unknown or waiting.
    pub(crate) amber: Color,
    /// Unknown or waiting, as a surface.
    pub(crate) amber_bg: Color,
}

impl Theme {
    /// Cleanroom's palette.
    pub(crate) const CLEANROOM: Self = Self {
        ink: INK,
        raised: RAISED,
        raised_hi: RAISED_HI,
        line: LINE,
        dim: DIM,
        muted: MUTED,
        text: TEXT,
        bright: BRIGHT,
        accent: ACCENT,
        accent_bg: ACCENT_BG,
        red: RED,
        red_bg: RED_BG,
        amber: AMBER,
        amber_bg: AMBER_BG,
    };

    /// A rounded panel with `title` inset in its top border. The focused panel's border and title
    /// are the bright accent; the others stay quiet.
    pub(crate) fn panel(&self, title: &str, focused: bool) -> Block<'static> {
        let (border, title_color) = if focused {
            (self.accent, self.accent)
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
