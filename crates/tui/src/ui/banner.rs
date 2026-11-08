//! The pixel-art banner over the Cleanroom tabs.
//!
//! A sealed lab, server racks, a lock, sentinel drones and a radar mast stand in silhouette
//! against a sky whose gradient tells the state of the incident at a glance. Every render builds a
//! character grid the width of the terminal, pastes each picture at a fraction of that width (so
//! the scene spreads out as the terminal widens) and draws each row in one style: the near-black
//! ink as the foreground, so the pictures read as silhouettes, and the row's gradient color as the
//! background.

use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::state::{State, compromised};
use crate::theme::{INK, RED};

/// Banner height in rows.
pub(super) const HEIGHT: u16 = 6;

/// The sky: what the gradient says about the incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sky {
    /// Nothing compromised and nothing waiting: deep ink to teal.
    Calm,
    /// Something waits for the commander's signature: dusk amber.
    Waiting,
    /// An asset is compromised: a red sunset.
    Breach,
    /// Compromised, and something waits for the commander: red sky down to an amber horizon.
    BreachWaiting,
}

impl Sky {
    /// The sky for `state`.
    pub(super) fn of(state: &State) -> Self {
        let breach = state.scope.iter().any(|asset| compromised(asset.flags));
        match (breach, state.waiting() > 0) {
            (false, false) => Self::Calm,
            (false, true) => Self::Waiting,
            (true, false) => Self::Breach,
            (true, true) => Self::BreachWaiting,
        }
    }

    /// One background per row, top to bottom.
    pub(super) const fn gradient(self) -> [Color; 6] {
        match self {
            Self::Calm => [
                Color::Rgb(9, 17, 26),
                Color::Rgb(10, 28, 38),
                Color::Rgb(12, 42, 50),
                Color::Rgb(14, 60, 64),
                Color::Rgb(20, 84, 82),
                Color::Rgb(30, 112, 104),
            ],
            Self::Waiting => [
                Color::Rgb(26, 18, 8),
                Color::Rgb(46, 30, 10),
                Color::Rgb(72, 46, 12),
                Color::Rgb(104, 66, 14),
                Color::Rgb(140, 90, 18),
                Color::Rgb(178, 118, 26),
            ],
            Self::Breach => [
                Color::Rgb(30, 6, 10),
                Color::Rgb(56, 9, 14),
                Color::Rgb(86, 13, 18),
                Color::Rgb(118, 18, 22),
                Color::Rgb(152, 26, 26),
                Color::Rgb(186, 40, 30),
            ],
            Self::BreachWaiting => [
                Color::Rgb(30, 6, 10),
                Color::Rgb(62, 10, 14),
                Color::Rgb(100, 16, 18),
                Color::Rgb(140, 34, 20),
                Color::Rgb(176, 70, 22),
                Color::Rgb(204, 112, 30),
            ],
        }
    }
}

/// A picture: rows of block characters, top to bottom, bottom-aligned by blank top rows; spaces
/// are transparent.
type Picture = &'static [&'static str];

/// The sealed cleanroom lab, with its air-handling stacks.
const LAB: Picture = &[
    "   ▗▖        ▗▖       ",
    "   ▐▌  ▗▄▄▄▄▖▐▌       ",
    " ▗▄▟▙▄▟██████▙▙▄▄▖    ",
    " ▐█▛▀▜█▛▀▜█▛▀▜█▛▀▜▌   ",
    " ▐█▙▄▟█▙▄▟█▙▄▟█▙▄▟███▖",
    "▄██████████████████████▄",
];

/// Three server racks.
const RACKS: Picture = &[
    "",
    " ▄▄▄  ▄▄▄  ▄▄▄",
    " █▀█  █▀█  █▀█",
    " █▄█  █▄█  █▄█",
    " █▀█  █▀█  █▀█",
    "▄█▄█▄▄█▄█▄▄█▄█▄",
];

/// A padlock, floating.
const LOCK: Picture = &["  ▗▛▀▜▖ ", "  ▐▌ ▐▌ ", " ▟████▙ ", " ██▛▜██ ", " ▜█▙▟█▛ "];

/// A sentinel drone on patrol.
const DRONE: Picture = &["▄▄▖   ▗▄▄", " ▝▜▙▄▟▛▘ ", "   ▝▀▘   "];

/// A smaller drone, further off.
const DRONE_FAR: Picture = &["", "▗▖ ▗▖", " ▝▀▘ "];

/// The radar mast.
const MAST: Picture = &[
    "  ▗▄▄▄▖  ",
    "   ▜█▛   ",
    "    █    ",
    "    █    ",
    "   ▟█▙   ",
    " ▄█████▄ ",
];

/// Where each picture sits: its left edge as a fraction of the width.
const SCENE: [(Picture, (usize, usize)); 6] = [
    (LAB, (2, 100)),
    (RACKS, (20, 100)),
    (LOCK, (40, 100)),
    (DRONE, (58, 100)),
    (DRONE_FAR, (70, 100)),
    (MAST, (84, 100)),
];

/// The ground along the bottom row, repeated.
const HORIZON: [char; 12] = ['▁', '▁', '▂', '▁', '▁', '▁', '▃', '▂', '▁', '▁', '▂', '▁'];

/// Draw the banner for `sky` into `area` (six rows). With a `clock` it moves: the drones drift on
/// patrol, the radar sweeps, and on a breach the beacon on the mast blinks red.
pub(super) fn render(frame: &mut Frame<'_>, area: Rect, sky: Sky, clock: Option<Timestamp>) {
    let width = usize::from(area.width);
    let millis = clock.map_or(0, |now| now.as_millisecond().rem_euclid(1 << 40));
    let drift = |period: i64, span: i64| {
        if clock.is_none() {
            return 0;
        }
        let step = (millis / period) % (2 * span);
        usize::try_from(if step < span { step } else { 2 * span - step }).unwrap_or(0)
    };
    let mut grid: Vec<Vec<char>> = (0..HEIGHT).map(|_| vec![' '; width]).collect();
    if let Some(ground) = grid.last_mut() {
        for (x, cell) in ground.iter_mut().enumerate() {
            *cell = HORIZON
                .get((x * 7 + x / 5) % HORIZON.len())
                .copied()
                .unwrap_or('▁');
        }
    }
    let mut mast = 0;
    for (index, (picture, (numerator, denominator))) in SCENE.into_iter().enumerate() {
        let left = width * numerator / denominator;
        let left = match index {
            3 => left + drift(420, 6),
            4 => left + drift(700, 4),
            5 => {
                mast = left;
                left
            }
            _ => left,
        };
        paste(&mut grid, picture, left);
    }
    if clock.is_some() {
        let beam = ['─', '╲', '│', '╱'];
        let frame_index = usize::try_from((millis / 250) % 4).unwrap_or(0);
        if let Some(cell) = grid.first_mut().and_then(|row| row.get_mut(mast + 10)) {
            *cell = beam.get(frame_index).copied().unwrap_or('─');
        }
    }
    let lines: Vec<Line<'static>> = grid
        .into_iter()
        .zip(sky.gradient())
        .map(|(row, color)| {
            Line::from(row.into_iter().collect::<String>()).style(Style::new().fg(INK).bg(color))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
    let breach = matches!(sky, Sky::Breach | Sky::BreachWaiting);
    if breach && clock.is_some() && (millis / 500) % 2 == 0 {
        let x = area
            .x
            .saturating_add(u16::try_from(mast + 4).unwrap_or(u16::MAX));
        if let Some(cell) = frame.buffer_mut().cell_mut((x, area.y)) {
            cell.set_symbol("●").set_fg(RED);
        }
    }
}

/// Paste the non-space characters of `picture` with its top-left corner at column `left`, cropped
/// at the right edge.
fn paste(grid: &mut [Vec<char>], picture: Picture, left: usize) {
    for (row, line) in grid.iter_mut().zip(picture) {
        for (offset, ch) in line.chars().enumerate() {
            if ch == ' ' {
                continue;
            }
            if let Some(cell) = row.get_mut(left + offset) {
                *cell = ch;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pictures_paste_without_spaces_and_crop_at_the_edge() {
        let mut grid = vec![vec!['x'; 4]; 2];
        paste(&mut grid, &["a b", "cdef"], 2);
        let rows: Vec<String> = grid.iter().map(|row| row.iter().collect()).collect();
        assert_eq!(
            rows,
            ["xxax", "xxcd"],
            "spaces keep what was there; d is cropped"
        );
    }
}
