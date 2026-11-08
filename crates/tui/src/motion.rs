//! Motion: short tachyonfx effects drawn over the finished frame. The console coalesces in at
//! startup, each tab fades in, and a red sweep crosses the screen when the kernel blocks a
//! command. Off under `NO_COLOR` or `--no-motion`; renders stay deterministic because effects
//! only touch the frame after `ui::render`.

use std::fmt;
use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use tachyonfx::{Effect, Interpolation, Motion as Sweep, fx};

use crate::state::{State, Talk};
use crate::theme::{INK, RED_BG};
use crate::ui::{Tab, View};

/// How long a newly arrived chat message keeps the console redrawing fast, for its fade-in.
const FADE_IN: Duration = Duration::from_millis(600);

/// Effects running over the frame and what they react to.
pub(crate) struct Motion {
    /// Running effects, oldest first.
    effects: Vec<Effect>,
    /// When the last frame was drawn.
    last: Instant,
    /// The tab the last frame showed.
    tab: Tab,
    /// Denials the last frame knew of.
    denials: usize,
    /// When the newest chat message the last frame knew of arrived.
    newest: Option<jiff::Timestamp>,
    /// Redraw fast until then (a message is fading in).
    fast_until: Instant,
}

impl fmt::Debug for Motion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Motion")
            .field("effects", &self.effects.len())
            .finish_non_exhaustive()
    }
}

impl Motion {
    /// Motion for a console opening on `view`: it starts by coalescing in.
    pub(crate) fn new(view: &View) -> Self {
        let now = Instant::now();
        Self {
            effects: vec![fx::coalesce((900, Interpolation::QuadOut))],
            last: now,
            tab: view.tab,
            denials: 0,
            newest: None,
            fast_until: now,
        }
    }

    /// Queue effects for what changed since the last frame.
    pub(crate) fn observe(&mut self, state: &State, view: &View) {
        let mut fresh = Vec::new();
        if view.tab != self.tab {
            self.tab = view.tab;
            fresh.push(fx::fade_from(INK, INK, (280, Interpolation::QuadOut)));
        }
        let denials = state.denials.all().len();
        if denials > self.denials {
            fresh.push(fx::sweep_in(
                Sweep::LeftToRight,
                48,
                0,
                RED_BG,
                (750, Interpolation::QuadOut),
            ));
        }
        self.denials = denials;
        let newest = state.talk.iter().rev().find_map(|talk| match talk {
            Talk::Said(said) => Some(said.arrived),
            Talk::Marker(_) => None,
        });
        if newest != self.newest {
            self.newest = newest;
            self.fast_until = Instant::now() + FADE_IN;
        }
        if !fresh.is_empty() {
            if self.effects.is_empty() {
                self.last = Instant::now();
            }
            self.effects.extend(fresh);
        }
    }

    /// Run every effect for the time since the last frame over `area` of `buf`, then drop the
    /// finished ones.
    pub(crate) fn process(&mut self, buf: &mut Buffer, area: Rect) {
        let elapsed = self.last.elapsed();
        self.last = Instant::now();
        for effect in &mut self.effects {
            effect.process(tachyonfx::Duration::from(elapsed), buf, area);
        }
        self.effects.retain(|effect| !effect.done());
    }

    /// Whether something is moving, so the console should redraw at about 30 fps.
    pub(crate) fn busy(&self) -> bool {
        !self.effects.is_empty() || Instant::now() < self.fast_until
    }
}
