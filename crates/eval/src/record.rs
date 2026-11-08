//! The raw run file and the eval's invocation log.
//!
//! A run file holds one JSON object per line: a header, every bus event the harness's human
//! connection received (with its time relative to the detonate request), and an end record
//! with what the harness measured after the agents finished. `report` scores runs from these
//! files alone. `eval.json` in the results directory lists every `run` invocation.

use std::fs;
use std::io::{BufWriter, ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{BusMessage, Signed};
use serde::{Deserialize, Serialize};

/// One line of a run file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Line {
    /// First line: what ran.
    Header(Header),
    /// A bus event.
    Event {
        /// Milliseconds after the detonate request (negative: before it).
        t_ms: i64,
        /// The event as received.
        event: Box<Signed<BusMessage>>,
    },
    /// Last line: what the harness measured after the run.
    End(End),
}

/// Where the agents' sensitive steps went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Route {
    /// Hosted NVIDIA API only.
    Hosted,
    /// Sensitive conversations routed to the local endpoint from `local.env`.
    Local,
}

impl Route {
    /// Lowercase name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::Local => "local",
        }
    }
}

/// Where model answers came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Llm {
    /// Live model calls, recorded for replay.
    Live,
    /// Answers replayed from a recording; no model network.
    Replay,
}

impl Llm {
    /// Lowercase name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Replay => "replay",
        }
    }
}

/// What ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Header {
    /// Run id, for example `baseline-off-hosted-1`.
    pub(crate) run: String,
    /// Variant (an answer key in `scenario/answers`).
    pub(crate) variant: String,
    /// The `detonate` scenario name.
    pub(crate) scenario: String,
    /// Agent guardrails at start.
    pub(crate) guardrails: bool,
    /// 1-based repetition.
    pub(crate) repetition: u32,
    /// Hosted only, or with the local route.
    pub(crate) route: Route,
    /// Live or replayed model answers.
    pub(crate) llm: Llm,
    /// `--max-steps` for the agents.
    pub(crate) max_steps: u32,
    /// When the run started, RFC 3339.
    pub(crate) started_at: String,
    /// Whether Hunter's standing YARA grant was in place before the detonation.
    pub(crate) yara_ready: bool,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Finish {
    /// The agents finished the investigation and exited.
    Finished,
    /// The agents exited with an error.
    AgentsFailed {
        /// Their exit code, if any.
        code: Option<i32>,
    },
    /// The run hit the time limit and the agents were stopped.
    TimedOut,
    /// The detonation failed, so the agents had nothing to investigate.
    DetonateFailed {
        /// The daemon's error.
        error: String,
    },
}

/// `verify_log` after a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct LogCheck {
    /// Receipts in the log.
    pub(crate) entries: u64,
    /// The first receipt that fails its signature or chain, if any.
    pub(crate) first_break: Option<u64>,
}

impl Finish {
    /// How the run ended, briefly.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Finished => "done".to_owned(),
            Self::AgentsFailed { code } => format!(
                "agents failed ({})",
                code.map_or_else(|| "signal".to_owned(), |code| format!("exit {code}"))
            ),
            Self::TimedOut => "timed out".to_owned(),
            Self::DetonateFailed { .. } => "detonate failed".to_owned(),
        }
    }
}

/// Agent `exec` receipts in the run's `receipts.ndjson`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct ReceiptCounts {
    /// Receipts in the log.
    pub(crate) total: u64,
    /// Agent commands the grant allowed.
    pub(crate) agent_exec_allowed: u32,
    /// Agent commands the grant denied.
    pub(crate) agent_exec_denied: u32,
}

/// What the harness measured after the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct End {
    /// Milliseconds after the detonate request when the run ended.
    pub(crate) t_ms: i64,
    /// How the run ended.
    pub(crate) finish: Finish,
    /// `verify_log` after the run, if the daemon answered.
    pub(crate) log: Option<LogCheck>,
    /// Agent command receipts.
    pub(crate) receipts: ReceiptCounts,
    /// Evidence files added (`+`), removed (`-`) or changed (`~`) after the detonation, by the
    /// path agents see. Hashed by the harness outside every sandbox.
    pub(crate) evidence_changed: Vec<String>,
    /// Model call retries in the agents' log (rate limits, timeouts, server errors).
    pub(crate) model_retries: u32,
    /// Retries caused by HTTP 429.
    pub(crate) rate_limited: u32,
}

/// One parsed run file.
#[derive(Debug)]
pub(crate) struct Run {
    /// Where it was read from.
    pub(crate) path: PathBuf,
    /// What ran.
    pub(crate) header: Header,
    /// Every event, with its time relative to the detonate request.
    pub(crate) events: Vec<(i64, Signed<BusMessage>)>,
    /// What the harness measured after the run.
    pub(crate) end: End,
}

/// Write a run file.
///
/// # Errors
/// Fails if the file cannot be written.
pub(crate) fn write_run(
    path: &Path,
    header: Header,
    events: Vec<(i64, Signed<BusMessage>)>,
    end: End,
) -> Result<()> {
    let partial = path.with_extension("jsonl.partial");
    let file = fs::File::create(&partial)
        .with_context(|| format!("cannot create {}", partial.display()))?;
    let mut out = BufWriter::new(file);
    let lines = std::iter::once(Line::Header(header))
        .chain(events.into_iter().map(|(t_ms, event)| Line::Event {
            t_ms,
            event: Box::new(event),
        }))
        .chain(std::iter::once(Line::End(end)));
    for line in lines {
        serde_json::to_writer(&mut out, &line).context("cannot encode a run line")?;
        out.write_all(b"\n")
            .with_context(|| format!("cannot write {}", partial.display()))?;
    }
    out.flush()
        .with_context(|| format!("cannot write {}", partial.display()))?;
    fs::rename(&partial, path)
        .with_context(|| format!("cannot move {} into place", partial.display()))
}

/// Read a run file.
///
/// # Errors
/// Fails if the file cannot be read, a line does not parse, or the header or end is missing.
pub(crate) fn read_run(path: &Path) -> Result<Run> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let (mut header, mut end, mut events) = (None, None, Vec::new());
    for (number, line) in text.lines().enumerate() {
        let parsed: Line = serde_json::from_str(line)
            .with_context(|| format!("{} line {} does not parse", path.display(), number + 1))?;
        match parsed {
            Line::Header(found) => header = Some(found),
            Line::Event { t_ms, event } => events.push((t_ms, *event)),
            Line::End(found) => end = Some(found),
        }
    }
    let (Some(header), Some(end)) = (header, end) else {
        bail!("{} has no header or no end record", path.display());
    };
    Ok(Run {
        path: path.to_owned(),
        header,
        events,
        end,
    })
}

/// Every run file in `dir/runs`, sorted by name.
///
/// # Errors
/// Fails if the directory cannot be listed.
pub(crate) fn run_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let runs = dir.join("runs");
    let mut files = Vec::new();
    let entries = match fs::read_dir(&runs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(files),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot list {}", runs.display()));
        }
    };
    for entry in entries {
        let path = entry
            .with_context(|| format!("cannot list {}", runs.display()))?
            .path();
        if path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// One `cleanroom-eval run` invocation, in `eval.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Invocation {
    /// The command line.
    pub(crate) command: String,
    /// When it started, RFC 3339.
    pub(crate) started_at: String,
    /// When it finished, if it did.
    pub(crate) finished_at: Option<String>,
    /// Hosted only, or with the local route.
    pub(crate) route: Route,
    /// Live or replayed model answers.
    pub(crate) llm: Llm,
    /// `--max-steps`.
    pub(crate) max_steps: u32,
    /// Repetitions per cell.
    pub(crate) repetitions: u32,
    /// `variant:on|off` cells.
    pub(crate) cells: Vec<String>,
    /// The repository commit.
    pub(crate) commit: String,
    /// Paths with uncommitted changes (`git status --porcelain`).
    pub(crate) dirty: Vec<String>,
    /// SHA-256 of each binary the runs used.
    pub(crate) binaries: Vec<(String, String)>,
}

/// The invocations recorded in `dir/eval.json`.
///
/// # Errors
/// Fails if the file exists but cannot be read or parsed.
pub(crate) fn invocations(dir: &Path) -> Result<Vec<Invocation>> {
    let path = dir.join("eval.json");
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not a list of invocations", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Replace `dir/eval.json`.
///
/// # Errors
/// Fails if the file cannot be written.
pub(crate) fn save_invocations(dir: &Path, invocations: &[Invocation]) -> Result<()> {
    let path = dir.join("eval.json");
    let mut text =
        serde_json::to_string_pretty(invocations).context("cannot encode the invocations")?;
    text.push('\n');
    fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))
}
