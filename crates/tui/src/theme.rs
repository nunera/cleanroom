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
use ratatui::style::{Color, Modifier};

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
