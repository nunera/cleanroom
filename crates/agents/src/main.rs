//! `cleanroom-agents`: the Nemotron agent team runner for Cleanroom.
//!
//! The runner holds one `cleanroomd` socket connection per agent role, waits for an
//! `investigate` bus event, and drives Hunter, Forensics, Scribe and Containment through
//! tool-calling loops against Nemotron. Every tool runs in the role's stratum through the
//! daemon, every publish is signed with the role's key, and every evidence-bearing tool output
//! passes the sensitivity router and the safety model before a model sees it. The Lead talks
//! with the commander: it narrates key events, answers questions and asks the specialists.
#![allow(
    clippy::redundant_pub_crate,
    reason = "binary crate: the strict profile denies rustc's `unreachable_pub`, which requires \
              `pub(crate)`; this nursery lint asks for the opposite. `allow`, not `expect`: nursery \
              lints only run under the strict profile"
)]

mod agent;
mod budget;
mod cache;
mod config;
mod daemon;
mod dataset;
mod egress;
mod gym;
mod keys;
mod lead;
mod llm;
mod narration;
mod pager;
mod records;
mod repair;
mod roles;
mod safety;
mod schema;
mod sensitivity;
mod situation;
mod team;
mod text;
mod tools;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

/// Nemotron agent team runner for Cleanroom.
#[derive(Debug, Parser)]
#[command(name = "cleanroom-agents", version, about)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Connect to cleanroomd, wait for `investigate` events and work each incident.
    Run(RunArgs),
    /// Export an incident's trainable model calls as NeMo Gym pivot rows
    /// (`single_step_tool_use_with_argument_comparison`). Needs the incident to have run with
    /// `CLEANROOM_LLM_CACHE=record`.
    ExportGym(ExportArgs),
}

/// `export-gym` options.
#[derive(Debug, Args)]
struct ExportArgs {
    /// Incident id, for example `INC-20261108-112348`.
    #[arg(long)]
    incident: String,
    /// Output JSONL path.
    #[arg(long)]
    out: PathBuf,
    /// Training tags directory [default: `$XDG_STATE_HOME/cleanroom/dataset`].
    #[arg(long)]
    dataset: Option<PathBuf>,
    /// Record cache directory [default: `$CLEANROOM_LLM_CACHE_DIR`, else `$XDG_CACHE_HOME/cleanroom/llm`].
    #[arg(long)]
    cache: Option<PathBuf>,
}

/// `run` options.
#[derive(Debug, Args)]
struct RunArgs {
    /// Start with the hardened prompts (on) or the naive ones (off); `agent_control` events
    /// switch at runtime.
    #[arg(long, value_enum, default_value_t = Switch::On)]
    guardrails: Switch,
    /// Maximum model calls per agent loop.
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..=100))]
    max_steps: u32,
    /// Path of the cleanroomd socket [default: `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`].
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Exit after the first investigation finishes.
    #[arg(long)]
    once: bool,
    /// Evidence pager: large attacker-written output enters an agent's context as a handle and
    /// is paged in on demand; tier maps go on the bus (`memory`) and to
    /// `$XDG_STATE_HOME/cleanroom/memory-tiers.ndjson`. `CLEANROOM_MEMORY_TIERS=1` also enables it.
    #[arg(long)]
    memory_tiers: bool,
}

/// `on` / `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Switch {
    /// Enabled.
    On,
    /// Disabled.
    Off,
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
    let args = match Cli::parse().command {
        Command::Run(args) => args,
        Command::ExportGym(args) => return export_gym(args),
    };
    let options = team::Options {
        guardrails: args.guardrails == Switch::On,
        max_steps: args.max_steps,
        socket: args.socket,
        once: args.once,
        memory_tiers: args.memory_tiers,
    };
    match team::run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// `export-gym`: write the pivot rows and print what was written and skipped.
fn export_gym(args: ExportArgs) -> ExitCode {
    let paths = || -> anyhow::Result<(PathBuf, PathBuf)> {
        let dataset = match args.dataset {
            Some(dir) => dir,
            None => config::xdg_dir("XDG_STATE_HOME", ".local/state")?.join("cleanroom/dataset"),
        };
        let cache = match args.cache {
            Some(dir) => dir,
            None => match std::env::var_os("CLEANROOM_LLM_CACHE_DIR").filter(|dir| !dir.is_empty())
            {
                Some(dir) => PathBuf::from(dir),
                None => config::xdg_dir("XDG_CACHE_HOME", ".cache")?.join("cleanroom/llm"),
            },
        };
        Ok((dataset, cache))
    };
    let result = paths()
        .and_then(|(dataset, cache)| gym::export(&dataset, &cache, &args.incident, &args.out));
    match result {
        Ok(summary) => {
            println!(
                "{} pivot rows -> {} ({:?}); skipped model calls: {:?}",
                summary.rows,
                args.out.display(),
                summary.actions,
                summary.skipped
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::from(2)
        }
    }
}
