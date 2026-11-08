//! `--replay`: play a recorded NDJSON frame stream at its recorded pace, with no socket.
//!
//! A recording is exactly what `--record` saves: the daemon's lines, verbatim. Bus events carry
//! their own `at`, which sets the pace; responses have no time of their own and follow the frame
//! before them immediately.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fmt, fs, io};

use cleanroom_proto::{Envelope, Frame};
use jiff::{SignedDuration, Timestamp};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::error::SendError;

use crate::app::Inbound;

/// Why a recording could not be loaded.
#[derive(Debug)]
pub(crate) enum ReplayError {
    /// The file could not be read.
    Read {
        /// The recording.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// A line is not an envelope.
    Parse {
        /// The recording.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What went wrong.
        source: serde_json::Error,
    },
    /// The file holds no frames.
    Empty {
        /// The recording.
        path: PathBuf,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "cannot read recording {}: {source}", path.display())
            }
            Self::Parse { path, line, source } => {
                write!(f, "{}:{line} is not a frame: {source}", path.display())
            }
            Self::Empty { path } => write!(f, "recording {} has no frames", path.display()),
        }
    }
}

impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Empty { .. } => None,
        }
    }
}

/// Read every frame in `path`. Blank lines are skipped; every other line must be an envelope.
///
/// # Errors
/// Fails when the file can't be read, a line isn't an envelope, or there are no frames.
pub(crate) fn load(path: &Path) -> Result<Vec<Envelope>, ReplayError> {
    let text = fs::read_to_string(path).map_err(|source| ReplayError::Read {
        path: path.to_owned(),
        source,
    })?;
    let frames = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|source| ReplayError::Parse {
                path: path.to_owned(),
                line: index + 1,
                source,
            })
        })
        .collect::<Result<Vec<Envelope>, _>>()?;
    if frames.is_empty() {
        return Err(ReplayError::Empty {
            path: path.to_owned(),
        });
    }
    Ok(frames)
}

/// When a frame happened, if it says: bus events carry `at`.
pub(crate) fn stamp(envelope: &Envelope) -> Option<Timestamp> {
    match &envelope.frame {
        Frame::Event(signed) => signed.body.at.parse().ok(),
        Frame::Hello { .. }
        | Frame::Publish(_)
        | Frame::Request { .. }
        | Frame::Response { .. } => None,
    }
}

/// Send `frames` to `inbound`, waiting between events for their recorded gap divided by
/// `speed`.
///
/// # Errors
/// Fails only when the console has already gone away.
pub(crate) async fn play(
    frames: Vec<Envelope>,
    speed: f64,
    inbound: UnboundedSender<Inbound>,
) -> Result<(), SendError<Inbound>> {
    let mut latest: Option<Timestamp> = None;
    for envelope in frames {
        if let Some(at) = stamp(&envelope) {
            if let Some(before) = latest {
                tokio::time::sleep(scaled_gap(at.duration_since(before), speed)).await;
            }
            latest = Some(latest.map_or(at, |before| before.max(at)));
        }
        inbound.send(Inbound::Frame(Box::new(envelope)))?;
    }
    inbound.send(Inbound::ReplayDone)
}

/// Real time to wait for a recorded `gap` at `speed`. Out-of-order frames don't wait.
fn scaled_gap(gap: SignedDuration, speed: f64) -> Duration {
    if gap.is_negative() {
        return Duration::ZERO;
    }
    Duration::try_from_secs_f64(gap.as_secs_f64() / speed).unwrap_or(Duration::ZERO)
}
