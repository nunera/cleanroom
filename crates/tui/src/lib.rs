//! Cleanroom incident command center.
//!
//! A ratatui console for the incident commander. It connects to `cleanroomd` over its Unix
//! socket (see `docs/interfaces.md`) and renders everything purely from daemon frames: the
//! **Cleanroom** screen (the conversation with the Lead agent, the team and the situation) and
//! the **Controlroom** screen (pinned OS denials, legal clocks, scope, the agent trace,
//! approvals, timeline and comms). It sends signed chat, approvals, enrollments, revocations and
//! requests back. `--replay` plays a recorded frame stream without a daemon.
//!
//! [`state::State`] is the reducer and [`ui::render`] draws it; both are public so a recorded
//! frame stream can be rendered offline.

mod access;
mod app;
mod cli;
mod clocks;
mod denials;
mod keystore;
mod net;
mod next;
mod replay;
pub mod state;
mod team;
mod theme;
pub mod ui;

use std::path::PathBuf;
use std::process::ExitCode;
use std::{env, fmt, io};

use clap::Parser as _;
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use tokio::sync::mpsc;

use crate::app::{App, Session};
use crate::cli::Args;
use crate::keystore::KeyError;
use crate::net::Recorder;
use crate::replay::ReplayError;
use crate::state::State;
use crate::theme::Colors;
use crate::ui::View;

/// Why the console could not start or had to stop.
#[derive(Debug)]
enum StartError {
    /// The async runtime could not be built.
    Runtime(io::Error),
    /// The commander key could not be loaded or created.
    Key(KeyError),
    /// No socket path was given and `XDG_RUNTIME_DIR` is unset.
    NoRuntimeDir,
    /// The `--record` file could not be created.
    Record {
        /// The recording path.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// cleanroomd is not reachable.
    Connect {
        /// The socket path.
        socket: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The `--replay` file could not be loaded.
    Replay(ReplayError),
    /// The terminal could not be set up, drawn to, or restored.
    Terminal(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "cannot start the async runtime: {error}"),
            Self::Key(error) => error.fmt(f),
            Self::NoRuntimeDir => f.write_str(
                "XDG_RUNTIME_DIR is not set, so cleanroomd's socket can't be found; pass --socket PATH",
            ),
            Self::Record { path, source } => {
                write!(f, "cannot create recording {}: {source}", path.display())
            }
            Self::Connect { socket, source } => write!(
                f,
                "cannot reach cleanroomd at {}: {source}\n\
                 Is cleanroomd running? To play a recorded demo instead: cleanroom-tui --replay FILE.ndjson",
                socket.display()
            ),
            Self::Replay(error) => error.fmt(f),
            Self::Terminal(error) => write!(f, "terminal error: {error}"),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(source)
            | Self::Terminal(source)
            | Self::Record { source, .. }
            | Self::Connect { source, .. } => Some(source),
            Self::Key(source) => Some(source),
            Self::Replay(source) => Some(source),
            Self::NoRuntimeDir => None,
        }
    }
}

impl From<KeyError> for StartError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<ReplayError> for StartError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}

/// Entry point of the `cleanroom-tui` binary: parse flags, run the console, and report a
/// failure on stderr.
#[must_use]
pub fn run() -> ExitCode {
    match start(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Print a fatal error once the terminal is back to normal.
#[allow(
    clippy::print_stderr,
    reason = "the binary's single fatal-error report. `allow`, not `expect`: the lint only runs \
              under the strict profile"
)]
fn report(error: &StartError) {
    eprintln!("cleanroom-tui: {error}");
}

/// Build the runtime and run the console on it.
///
/// # Errors
/// Fails when the runtime can't start or the console fails; see [`console`].
fn start(args: Args) -> Result<(), StartError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(StartError::Runtime)?
        .block_on(console(args))
}

/// Connect (or load the recording) before touching the terminal, so startup errors print
/// normally; then run the console and restore the terminal.
///
/// # Errors
/// Fails when the key, socket, recording or terminal is unusable.
async fn console(args: Args) -> Result<(), StartError> {
    let state = State::new(TimeZone::system());
    let colors = Colors::from_env();
    let (inbound, frames) = mpsc::unbounded_channel();
    let app = if let Some(path) = &args.replay {
        let recording = replay::load(path)?;
        let start = recording
            .iter()
            .find_map(replay::stamp)
            .unwrap_or_else(Timestamp::now);
        tokio::spawn(replay::play(recording, args.speed, inbound));
        let view = View::replay(args.speed).with_colors(colors);
        App::replay(state, view, start, args.speed)
    } else {
        let key = keystore::load_or_create(&keystore::commander_key_path()?)?;
        let socket = match args.socket {
            Some(socket) => socket,
            None => default_socket()?,
        };
        let recorder = match args.record {
            Some(path) => Some(
                Recorder::create(&path)
                    .await
                    .map_err(|source| StartError::Record { path, source })?,
            ),
            None => None,
        };
        let outbound = net::connect(&socket, &app::hello(&key), recorder, inbound)
            .await
            .map_err(|source| StartError::Connect { socket, source })?;
        let view = View::live(args.scenarios).with_colors(colors);
        App::live(state, view, Session::new(key, outbound), args.tamper_root)
    };
    let mut terminal = ratatui::try_init().map_err(StartError::Terminal)?;
    // Bracketed paste delivers a pasted public key as one event instead of keystrokes, so a
    // trailing newline in the clipboard cannot submit a half-filled form.
    let pasting = crossterm::execute!(io::stdout(), EnableBracketedPaste);
    let outcome = match pasting {
        Ok(()) => app::run(&mut terminal, app, frames).await,
        Err(error) => Err(error),
    };
    let unpasted = crossterm::execute!(io::stdout(), DisableBracketedPaste);
    let restored = ratatui::try_restore();
    outcome
        .and(unpasted)
        .and(restored)
        .map_err(StartError::Terminal)
}

/// `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`.
///
/// # Errors
/// Fails when `XDG_RUNTIME_DIR` is unset.
fn default_socket() -> Result<PathBuf, StartError> {
    env::var_os("XDG_RUNTIME_DIR")
        .filter(|dir| !dir.is_empty())
        .map(|dir| PathBuf::from(dir).join("cleanroom").join("cleanroomd.sock"))
        .ok_or(StartError::NoRuntimeDir)
}
