//! `cleanroomd`: the Cleanroom OS core.
//!
//! One Unix socket carries the bus and the daemon operations (`docs/interfaces.md`). The daemon
//! admits digest-pinned roots, runs commands in bubblewrap strata under per-role grants, admits
//! tools from pinned nixpkgs, keeps a signed hash-chained receipt log, and runs the acme-fs
//! ransomware scenario.
#![allow(
    clippy::redundant_pub_crate,
    reason = "binary crate: the strict profile denies rustc's `unreachable_pub`, which requires \
              `pub(crate)`; this nursery lint asks for the opposite. `allow`, not `expect`: nursery \
              lints only run under the strict profile"
)]

mod bus;
mod client;
mod daemon;
mod keys;
mod layout;
mod members;
mod receipts;
mod roots;
mod scenario;
mod server;
mod strata;
mod tools;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cleanroom_proto::Timestamp;
use tracing_subscriber::EnvFilter;

use crate::daemon::Daemon;
use crate::layout::Layout;

/// Cleanroom OS core: root admission, strata, grants, receipts, the bus and the scenarios.
///
/// Without a command, serve on the socket until interrupted.
#[derive(Debug, Parser)]
#[command(name = "cleanroomd", version, about)]
struct Cli {
    /// Socket path [default: `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`].
    #[arg(long, value_name = "PATH", global = true)]
    socket: Option<PathBuf>,
    /// State directory [default: `$XDG_STATE_HOME/cleanroom`, else `~/.local/state/cleanroom`].
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
    /// Repository holding `scenario/` and `roots/` [default: the nearest ancestor of this binary
    /// that has both, else the current directory].
    #[arg(long, value_name = "DIR")]
    repo: Option<PathBuf>,
    /// A one-shot client command against the running daemon.
    #[command(subcommand)]
    command: Option<Command>,
}

/// One-shot client commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Ask the running daemon to admit a root. Exits 0 when admitted, 1 when rejected, 2 on
    /// errors.
    Admit {
        /// Root name, for example `debian`.
        root: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Admit { root }) => match admit(cli.socket, &root).await {
            Ok(code) => code,
            Err(error) => {
                tracing::error!("{error:#}");
                ExitCode::from(2)
            }
        },
        None => match serve(cli).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                tracing::error!("{error:#}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Bind the socket first (so a second daemon refuses before touching state), start the daemon,
/// then serve until interrupted.
///
/// # Errors
/// Fails if the paths, socket, keys, receipt log or scenario files are unusable.
async fn serve(cli: Cli) -> Result<()> {
    let layout = Layout::resolve(cli.socket, cli.state, cli.repo)?;
    let listener = server::bind(&layout.socket)?;
    let socket = layout.socket.clone();
    let daemon = Daemon::start(layout).await?;
    server::serve(daemon, listener, &socket).await
}

/// `cleanroomd admit <root>`.
///
/// # Errors
/// Fails if the socket path cannot be resolved or the daemon cannot answer.
async fn admit(socket: Option<PathBuf>, root: &str) -> Result<ExitCode> {
    let socket = match socket {
        Some(socket) => socket,
        None => layout::default_socket()?,
    };
    client::admit(&socket, root).await
}

/// The current time as an RFC 3339 UTC timestamp with seconds precision.
pub(crate) fn now() -> Timestamp {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

/// Lock `mutex`. Every critical section leaves its data consistent, so a panic elsewhere cannot
/// poison anything that matters; the poison flag is ignored.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
