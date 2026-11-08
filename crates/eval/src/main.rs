//! `cleanroom-eval`: the Cleanroom eval harness.
//!
//! `run` drives the real stack once per (variant, guardrails, repetition): an isolated
//! `cleanroomd`, the Debian root admitted, `cleanroom-agents run --once`, and a human
//! connection that detonates the variant and records every bus event until the team is done.
//! Each run becomes one raw JSONL file. `report` scores those files against
//! `scenario/answers/<variant>.json` and writes the Markdown report.
#![allow(
    clippy::redundant_pub_crate,
    reason = "binary crate: the strict profile denies rustc's `unreachable_pub`, which requires \
              `pub(crate)`; this nursery lint asks for the opposite. `allow`, not `expect`: nursery \
              lints only run under the strict profile"
)]

mod answers;
mod evidence;
mod link;
mod matchers;
mod record;
mod report;
mod runner;
mod score;

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand};
use sha2::{Digest as _, Sha256};
use tracing_subscriber::EnvFilter;

use crate::record::{Invocation, Llm, Route};
use crate::runner::{Bins, Case, Plan};
use crate::score::Judge;

/// The default eval: the four attack variants with guardrails off and on, plus the control
/// with guardrails on.
const DEFAULT_CELLS: [&str; 9] = [
    "baseline:off",
    "baseline:on",
    "logpoison:off",
    "logpoison:on",
    "credexfil:off",
    "credexfil:on",
    "stealth:off",
    "stealth:on",
    "benign:on",
];

/// Cleanroom eval harness: run the agent team against attack variants and score every layer.
#[derive(Debug, Parser)]
#[command(name = "cleanroom-eval", version, about)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run the eval against the real stack and write one raw JSONL file per run.
    Run(RunArgs),
    /// Score run files against the answer keys and write the Markdown report.
    Report(ReportArgs),
}

/// `run` options.
#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches. `allow`, not `expect`: the lint only runs under \
              the strict Clippy profile"
)]
struct RunArgs {
    /// A cell to run, as `variant:on` or `variant:off` (guardrails); repeat for several.
    /// [default: baseline, logpoison, credexfil and stealth with off and on, benign with on]
    #[arg(long = "cell", value_name = "VARIANT:ON|OFF")]
    cells: Vec<String>,
    /// Runs per cell.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=20))]
    repetitions: u32,
    /// Model calls per agent loop (`cleanroom-agents --max-steps`).
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
    max_steps: u32,
    /// Route sensitive steps to the local endpoint in `~/.config/cleanroom/local.env` (Brev on
    /// 127.0.0.1:8000; start its tunnel first).
    #[arg(long)]
    local: bool,
    /// Replay the model answers recorded by an earlier live eval; no model network.
    #[arg(long)]
    replay: bool,
    /// Repository root [default: the current directory].
    #[arg(long, value_name = "DIR")]
    repo: Option<PathBuf>,
    /// Where `cleanroomd` and `cleanroom-agents` are [default: `<repo>/target/release`].
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<PathBuf>,
    /// The static `cleanroom-ransom` [default:
    /// `<repo>/target/x86_64-unknown-linux-musl/release/cleanroom-ransom`].
    #[arg(long, value_name = "FILE")]
    ransom: Option<PathBuf>,
    /// Scratch root for per-run daemon state, sockets and logs.
    #[arg(long, value_name = "DIR", default_value = "/tmp/cleanroom-dev/eval")]
    work: PathBuf,
    /// Results directory [default: `<repo>/crates/eval/results/<date>-<route>[-replay]`].
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// Root of the per-run model recordings [default: `$XDG_CACHE_HOME/cleanroom/eval`].
    #[arg(long, value_name = "DIR")]
    llm_cache: Option<PathBuf>,
    /// Longest a run may take after the detonation, in minutes.
    #[arg(long, default_value_t = 20)]
    run_timeout_min: u64,
    /// Pause between runs, in seconds (gentle on the hosted API).
    #[arg(long, default_value_t = 5)]
    pause_s: u64,
    /// Keep each run's daemon state and logs.
    #[arg(long)]
    keep_state: bool,
}

/// `report` options.
#[derive(Debug, Args)]
struct ReportArgs {
    /// A results directory written by `run`; repeat for several.
    #[arg(long = "results", value_name = "DIR", required = true)]
    results: Vec<PathBuf>,
    /// Where to write the report.
    #[arg(long, value_name = "FILE", default_value = "docs/eval.md")]
    out: PathBuf,
    /// Repository root [default: the current directory].
    #[arg(long, value_name = "DIR")]
    repo: Option<PathBuf>,
}

/// Parse the command line and run it.
///
/// # Panics
/// Panics if the Tokio runtime cannot be built.
#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let result = match Cli::parse().command {
        Command::Run(args) => tokio::select! {
            result = run(args) => result,
            interrupt = tokio::signal::ctrl_c() => interrupt
                .context("cannot listen for Ctrl-C")
                .and_then(|()| bail!("interrupted; finished runs are kept and a rerun resumes")),
        },
        Command::Report(args) => report(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// `cleanroom-eval run`.
///
/// # Errors
/// Fails on bad options, missing binaries or answer keys, or a stack that cannot come up.
async fn run(args: RunArgs) -> Result<()> {
    let repo = repo_root(args.repo.as_deref())?;
    let route = if args.local {
        Route::Local
    } else {
        Route::Hosted
    };
    let llm = if args.replay { Llm::Replay } else { Llm::Live };
    let cases = cases(&repo, &args.cells, args.repetitions)?;
    let classifier = matchers::Classifier::new().context("compiling the classifiers")?;
    let judge = Judge::new(classifier, answers::vpn_secrets(&repo)?);
    let out = args.out.clone().unwrap_or_else(|| {
        repo.join("crates/eval/results")
            .join(default_label(route, llm))
    });
    fs::create_dir_all(&out).with_context(|| format!("cannot create {}", out.display()))?;
    let bins = snapshot(&repo, &args)?;
    let plan = Plan {
        llm_cache: args.llm_cache.clone().map_or_else(cache_root, Ok)?,
        agent_env: if args.local { local_env()? } else { Vec::new() },
        bins,
        repo,
        work: args.work.clone(),
        out,
        route,
        llm,
        max_steps: args.max_steps,
        run_timeout: Duration::from_secs(args.run_timeout_min.saturating_mul(60)),
        keep_state: args.keep_state,
    };
    let mut invocations = record::invocations(&plan.out)?;
    invocations.push(invocation(&plan, &args)?);
    record::save_invocations(&plan.out, &invocations)?;
    for (index, case) in cases.iter().enumerate() {
        if let Some(path) = runner::finished(&plan, case) {
            tracing::info!(
                "{} already has {}; skipping",
                case.id(route),
                path.display()
            );
            continue;
        }
        tracing::info!("run {}/{}: {}", index + 1, cases.len(), case.id(route));
        let path = runner::run(&plan, case).await?;
        let run = record::read_run(&path)?;
        let key = answers::load(&plan.repo, &case.variant)?;
        let score = judge.score(&run, &key);
        tracing::info!("{}: {}", case.id(route), report::summary(&score));
        if index + 1 < cases.len() {
            tokio::time::sleep(Duration::from_secs(args.pause_s)).await;
        }
    }
    if let Some(last) = invocations.last_mut() {
        last.finished_at = Some(runner::now());
    }
    record::save_invocations(&plan.out, &invocations)?;
    let report_path = plan.out.join("report.md");
    write_report(
        &plan.repo,
        std::slice::from_ref(&plan.out),
        &judge,
        &report_path,
    )?;
    writeln!(io::stdout().lock(), "{}", report_path.display()).context("writing to stdout")
}

/// `cleanroom-eval report`.
///
/// # Errors
/// Fails if a run file or answer key cannot be read or the report cannot be written.
fn report(args: &ReportArgs) -> Result<()> {
    let repo = repo_root(args.repo.as_deref())?;
    let classifier = matchers::Classifier::new().context("compiling the classifiers")?;
    let judge = Judge::new(classifier, answers::vpn_secrets(&repo)?);
    write_report(&repo, &args.results, &judge, &args.out)?;
    writeln!(io::stdout().lock(), "{}", args.out.display()).context("writing to stdout")
}

/// Score `dirs` and write the report to `path`, keeping its notes block.
///
/// # Errors
/// Fails if a directory cannot be resolved, a run or key cannot be read, or the report cannot
/// be written.
fn write_report(repo: &Path, dirs: &[PathBuf], judge: &Judge, path: &Path) -> Result<()> {
    let mut resolved = Vec::with_capacity(dirs.len());
    for dir in dirs {
        resolved.push(
            fs::canonicalize(dir).with_context(|| format!("cannot resolve {}", dir.display()))?,
        );
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let report_dir =
        fs::canonicalize(parent).with_context(|| format!("cannot resolve {}", parent.display()))?;
    let (results, keys) = report::load(repo, &resolved, judge)?;
    let notes = report::existing_notes(path)?;
    let place = report::Place {
        repo,
        report_dir: &report_dir,
    };
    let text = report::render(&results, &keys, notes.as_deref(), place);
    fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

/// The cases to run, repetition-major so a partial eval stays balanced.
///
/// # Errors
/// Fails on a malformed cell or a variant without an answer key.
fn cases(repo: &Path, cells: &[String], repetitions: u32) -> Result<Vec<Case>> {
    let cells: Vec<String> = if cells.is_empty() {
        DEFAULT_CELLS
            .iter()
            .map(|cell| (*cell).to_owned())
            .collect()
    } else {
        cells.to_vec()
    };
    let mut parsed = Vec::with_capacity(cells.len());
    for cell in &cells {
        let (variant, guardrails) = cell
            .split_once(':')
            .with_context(|| format!("cell `{cell}` is not variant:on or variant:off"))?;
        let guardrails = match guardrails {
            "on" => true,
            "off" => false,
            other => bail!("cell `{cell}`: guardrails must be on or off, not `{other}`"),
        };
        let key = answers::load(repo, variant)?;
        parsed.push((key.variant, key.scenario, guardrails));
    }
    Ok((1..=repetitions)
        .flat_map(|repetition| {
            parsed
                .iter()
                .map(move |(variant, scenario, guardrails)| Case {
                    variant: variant.clone(),
                    scenario: scenario.clone(),
                    guardrails: *guardrails,
                    repetition,
                })
        })
        .collect())
}

/// Copy the binaries into the work directory so a rebuild mid-eval cannot change them.
///
/// # Errors
/// Fails if a binary is missing or cannot be copied.
fn snapshot(repo: &Path, args: &RunArgs) -> Result<Bins> {
    let bin_dir = args
        .bin_dir
        .clone()
        .unwrap_or_else(|| repo.join("target/release"));
    let ransom = args
        .ransom
        .clone()
        .unwrap_or_else(|| repo.join("target/x86_64-unknown-linux-musl/release/cleanroom-ransom"));
    let target = args.work.join("bin");
    fs::create_dir_all(&target).with_context(|| format!("cannot create {}", target.display()))?;
    let copy = |source: &Path, name: &str| -> Result<PathBuf> {
        if !source.is_file() {
            bail!(
                "{} is missing; build it first (see docs/eval.md)",
                source.display()
            );
        }
        let copied = target.join(name);
        fs::copy(source, &copied)
            .with_context(|| format!("cannot copy {} to {}", source.display(), copied.display()))?;
        Ok(copied)
    };
    Ok(Bins {
        daemon: copy(&bin_dir.join("cleanroomd"), "cleanroomd")?,
        agents: copy(&bin_dir.join("cleanroom-agents"), "cleanroom-agents")?,
        ransom: copy(&ransom, "cleanroom-ransom")?,
    })
}

/// What this invocation runs, for `eval.json`.
///
/// # Errors
/// Fails if a binary cannot be hashed.
fn invocation(plan: &Plan, args: &RunArgs) -> Result<Invocation> {
    let mut binaries = Vec::with_capacity(3);
    for path in [&plan.bins.daemon, &plan.bins.agents, &plan.bins.ransom] {
        let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let name = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        binaries.push((name, hex::encode(Sha256::digest(&bytes))));
    }
    let cells = if args.cells.is_empty() {
        DEFAULT_CELLS
            .iter()
            .map(|cell| (*cell).to_owned())
            .collect()
    } else {
        args.cells.clone()
    };
    Ok(Invocation {
        command: command_line(),
        started_at: runner::now(),
        finished_at: None,
        route: plan.route,
        llm: plan.llm,
        max_steps: plan.max_steps,
        repetitions: args.repetitions,
        cells,
        commit: git(&plan.repo, &["rev-parse", "HEAD"])?.trim().to_owned(),
        dirty: git(&plan.repo, &["status", "--porcelain"])?
            .lines()
            .map(|line| line.get(3..).unwrap_or(line).to_owned())
            .collect(),
        binaries,
    })
}

/// This process's command line, with the program shown by name.
fn command_line() -> String {
    std::env::args()
        .enumerate()
        .map(|(index, arg)| {
            if index == 0 {
                Path::new(&arg)
                    .file_name()
                    .map_or_else(|| arg.clone(), |name| name.to_string_lossy().into_owned())
            } else {
                arg
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run `git` in `repo` and return its output.
///
/// # Errors
/// Fails if git cannot run or fails.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .context("cannot run git")?;
    if !output.status.success() {
        bail!("git {} failed", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `--repo`, else the current directory; it must hold the answer keys.
///
/// # Errors
/// Fails if the directory cannot be resolved or has no `scenario/answers`.
fn repo_root(repo: Option<&Path>) -> Result<PathBuf> {
    let repo = match repo {
        Some(repo) => repo.to_owned(),
        None => std::env::current_dir().context("cannot read the current directory")?,
    };
    let repo =
        fs::canonicalize(&repo).with_context(|| format!("cannot resolve {}", repo.display()))?;
    if !repo.join("scenario/answers").is_dir() {
        bail!(
            "{} has no scenario/answers; run from the repository root or pass --repo",
            repo.display()
        );
    }
    Ok(repo)
}

/// `<date>-<route>[-replay]`.
fn default_label(route: Route, llm: Llm) -> String {
    let date = runner::now().get(..10).unwrap_or_default().to_owned();
    match llm {
        Llm::Live => format!("{date}-{}", route.name()),
        Llm::Replay => format!("{date}-{}-replay", route.name()),
    }
}

/// `$XDG_CACHE_HOME/cleanroom/eval`, else `~/.cache/cleanroom/eval`.
///
/// # Errors
/// Fails if neither variable is set.
fn cache_root() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .context("neither XDG_CACHE_HOME nor HOME is set; pass --llm-cache")?,
        )
        .join(".cache"),
    };
    Ok(base.join("cleanroom/eval"))
}

/// The variables in `~/.config/cleanroom/local.env` (`KEY=VALUE` lines, comments, `export`
/// and quotes allowed). Values are passed to the agents only, never printed.
///
/// # Errors
/// Fails if the file cannot be read or sets nothing.
fn local_env() -> Result<Vec<(String, String)>> {
    let config = match std::env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    let path = config.join("cleanroom/local.env");
    let text =
        fs::read_to_string(&path).with_context(|| format!("--local needs {}", path.display()))?;
    let vars: Vec<(String, String)> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            let value = value.trim();
            let value = ['"', '\'']
                .into_iter()
                .find_map(|quote| value.strip_prefix(quote)?.strip_suffix(quote))
                .unwrap_or(value);
            Some((key.trim().to_owned(), value.to_owned()))
        })
        .collect();
    if vars.is_empty() {
        bail!("{} sets no variables", path.display());
    }
    tracing::info!(
        "local route: {} variables from {} ({})",
        vars.len(),
        path.display(),
        vars.iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(vars)
}
