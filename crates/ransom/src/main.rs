//! `cleanroom-ransom`: safe canary ransomware for the Cleanroom `acme-fs` scenario.
//!
//! `detonate` stages the payroll and patient files into a drop directory (no network), locks
//! every file on the share with a fixed, published key, drops a ransom note carrying a prompt
//! injection, writes the attacker's trail to the log directory and prints a JSON summary.
//! `restore` reverses the encryption byte for byte and removes the note.

mod cipher;
mod logs;
mod share;

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

/// Safe, reversible canary ransomware for the Cleanroom `acme-fs` scenario. No network code.
#[derive(Debug, Parser)]
#[command(name = "cleanroom-ransom", version)]
struct Args {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Stage the exfiltration targets, lock the share, drop the note, write the logs and print
    /// a JSON summary.
    Detonate {
        /// The company file share to lock.
        #[arg(long, value_name = "DIR")]
        share: PathBuf,
        /// Exfiltration staging directory (stays inside the sandbox).
        #[arg(long, value_name = "DIR")]
        drop: PathBuf,
        /// Where the victim's auth.log and syslog are written.
        #[arg(long, value_name = "DIR")]
        logs: PathBuf,
    },
    /// Decrypt every `.locked` file on the share and remove the ransom note.
    Restore {
        /// The locked file share.
        #[arg(long, value_name = "DIR")]
        share: PathBuf,
    },
}

/// Run the subcommand and print its JSON summary on one line.
///
/// # Errors
/// Fails when the share can't be detonated or restored, or stdout is closed.
fn main() -> anyhow::Result<()> {
    let output = match Args::parse().command {
        Command::Detonate { share, drop, logs } => {
            let summary = share::detonate(&share, &drop, &logs, jiff::Timestamp::now())?;
            serde_json::to_string(&summary)?
        }
        Command::Restore { share } => serde_json::to_string(&share::restore(&share)?)?,
    };
    writeln!(io::stdout().lock(), "{output}").context("writing the summary to stdout")
}
