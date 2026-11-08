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
mod plan;
mod probe;
mod reasoning;
mod receipts;
mod roots;
mod rules;
mod scenario;
mod server;
mod strata;
mod tools;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use clap::{Parser, Subcommand};
use cleanroom_proto::{CoreRequest, Timestamp};
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

/// One-shot client commands against the running daemon. Each exits 2 on errors (no daemon, a
/// refused request).
#[derive(Debug, Subcommand)]
enum Command {
    /// Admit a root. Exits 0 when admitted, 1 when rejected.
    Admit {
        /// Root name, for example `debian`.
        root: String,
    },
    /// Verify every receipt's signature and the hash chain. Exits 0 when intact, 1 when broken.
    Verify,
    /// Restore the victim share and close the incident; the receipt log is kept.
    Reset,
    /// Detonate a scenario in the victim stratum and start the investigation.
    Detonate {
        /// Scenario name.
        #[arg(default_value = "ransomware")]
        scenario: String,
    },
    /// Flip one byte in a staged copy of a root, so the next `admit` is rejected.
    Tamper {
        /// Root name.
        #[arg(default_value = "debian")]
        root: String,
    },
    /// Run a command in an agent's stratum under that agent's grant, as that agent. Exits with
    /// the command's code, 124 on timeout, 126 when the grant denies it.
    Run {
        /// Agent stratum: hunter, forensics, scribe or containment.
        stratum: String,
        /// Seconds before the sandbox is killed.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Program and arguments, after `--`.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Test a stratum's walls from inside it (network, capabilities, nested user namespaces,
    /// environment, read-only evidence, host home), one signed receipt per wall. Exits 0 when
    /// every wall holds, 1 when one is broken.
    Probe {
        /// Agent stratum that runs commands: hunter or forensics.
        #[arg(default_value = "hunter")]
        stratum: String,
    },
    /// Show the Nemotron reasoning behind a `model_call` receipt, offline from the state
    /// directory, and check it against the digest the daemon signed. Exits 0 when it matches, 1
    /// when the stored trace was changed.
    Reasoning {
        /// The receipt number.
        seq: u64,
        /// State directory [default: `$XDG_STATE_HOME/cleanroom`, else `~/.local/state/cleanroom`].
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
    },
    /// Work with declarative host plans offline (no daemon needed).
    Plan {
        /// What to do with the plan.
        #[command(subcommand)]
        action: PlanAction,
    },
}

/// `cleanroomd plan` actions.
#[derive(Debug, Subcommand)]
enum PlanAction {
    /// Check a plan (unique names, declared dependencies, no cycles) and print its boot order.
    /// Exits 0 valid, 1 invalid, 2 unreadable.
    Validate {
        /// The plan file, for example `plans/responder.json`.
        file: PathBuf,
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
        Some(command) => match client_command(cli.socket, command).await {
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

/// Run one client command: against the daemon on `socket` (default: the usual path), or
/// offline for `plan`.
///
/// # Errors
/// Fails if the socket path cannot be resolved or the daemon cannot answer.
async fn client_command(socket: Option<PathBuf>, command: Command) -> Result<ExitCode> {
    let socket = || match &socket {
        Some(socket) => Ok(socket.clone()),
        None => layout::default_socket(),
    };
    match command {
        Command::Plan {
            action: PlanAction::Validate { file },
        } => Ok(plan::validate_file(&file)),
        Command::Reasoning { seq, state } => {
            let state = match state {
                Some(state) => state,
                None => layout::default_state()?,
            };
            reasoning::command(&state, seq)
        }
        Command::Admit { root } => client::admit(&socket()?, &root).await,
        Command::Verify => client::verify(&socket()?).await,
        Command::Reset => {
            client::simple(
                &socket()?,
                CoreRequest::Reset,
                "reset: victim re-seeded, incident closed",
            )
            .await
        }
        Command::Detonate { scenario } => {
            let done = format!("detonated {scenario}; the investigation has started");
            client::simple(&socket()?, CoreRequest::Detonate { scenario }, &done).await
        }
        Command::Tamper { root } => {
            let done = format!("tampered a staged copy of {root}; the next admit is rejected");
            client::simple(&socket()?, CoreRequest::Tamper { root }, &done).await
        }
        Command::Run {
            stratum,
            timeout,
            argv,
        } => client::run(&socket()?, &stratum, argv, Duration::from_secs(timeout)).await,
        Command::Probe { stratum } => client::probe(&socket()?, &stratum).await,
    }
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
