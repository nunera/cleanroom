//! Command-line flags.

use std::path::PathBuf;

use clap::Parser;

use crate::theme::Name;

/// Cleanroom incident command center.
///
/// Connects to cleanroomd and shows the incident, the scope of compromised data, the legal
/// notification clocks, the agents' live trace and the approvals queue. Keys are listed at the
/// bottom of the screen; press ? inside the console for help.
#[derive(Debug, Parser)]
#[command(name = "cleanroom-tui", version)]
pub(crate) struct Args {
    /// Play a recorded NDJSON frame stream (from --record) instead of connecting to cleanroomd.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["record", "socket"])]
    pub(crate) replay: Option<PathBuf>,

    /// Replay speed multiplier: 2 plays twice as fast.
    #[arg(long, value_name = "X", default_value_t = 1.0, value_parser = parse_speed, requires = "replay")]
    pub(crate) speed: f64,

    /// Save every frame received from cleanroomd to FILE, for --replay later.
    #[arg(long, value_name = "FILE")]
    pub(crate) record: Option<PathBuf>,

    /// cleanroomd's socket [default: `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`].
    #[arg(long, value_name = "PATH")]
    pub(crate) socket: Option<PathBuf>,

    /// Root that `t` tampers with and tries to admit, and that `A` admits again.
    #[arg(long, value_name = "NAME", default_value = "debian")]
    pub(crate) tamper_root: String,

    /// Scenario offered by `d`; repeat the flag to offer several.
    #[arg(long = "scenario", value_name = "NAME", default_value = "ransomware")]
    pub(crate) scenarios: Vec<String>,

    /// Draw without animation (motion is also off under `NO_COLOR`).
    #[arg(long)]
    pub(crate) no_motion: bool,

    /// Color theme: cleanroom, ember, lavender, phosphor or projector. Overrides
    /// `CLEANROOM_THEME` and the theme last chosen with `T`.
    #[arg(long, value_name = "NAME", value_parser = parse_theme)]
    pub(crate) theme: Option<Name>,
}

/// A theme by name.
///
/// # Errors
/// Fails when no theme has that name.
fn parse_theme(text: &str) -> Result<Name, String> {
    Name::parse(text).ok_or_else(|| format!("unknown theme; choose one of {}", Name::listed()))
}

/// A playback speed between 0.01× and 1000×.
///
/// # Errors
/// Fails when `text` is not a number in that range.
fn parse_speed(text: &str) -> Result<f64, String> {
    let speed: f64 = text.parse().map_err(|error| format!("{error}"))?;
    if speed.is_finite() && (0.01..=1000.0).contains(&speed) {
        Ok(speed)
    } else {
        Err("speed must be between 0.01 and 1000".to_owned())
    }
}
