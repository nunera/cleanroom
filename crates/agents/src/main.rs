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
mod cache;
mod config;
mod daemon;
mod dataset;
mod egress;
mod keys;
mod lead;
mod llm;
mod narration;
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
    let Command::Run(args) = Cli::parse().command;
    let options = team::Options {
        guardrails: args.guardrails == Switch::On,
        max_steps: args.max_steps,
        socket: args.socket,
        once: args.once,
    };
    match team::run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
