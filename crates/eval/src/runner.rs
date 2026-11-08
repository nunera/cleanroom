//! One eval run, end to end, against the real stack.
//!
//! A fresh `cleanroomd` gets its own socket and state under the work directory (the OCI store
//! is shared so each image is fetched once). The harness connects as a human, admits `debian`
//! and `alpine`, waits for Hunter's standing YARA grant, starts `cleanroom-agents run --once`,
//! detonates the variant and records every bus event until the agents exit. It rejects every
//! containment proposal and every tool request that waits for a commander, so no run stalls on
//! a human. Afterwards it verifies the receipt log, hashes the evidence again and writes the
//! run file.

use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{BusBody, BusMessage, CoreRequest, CoreResponse, Principal, Signed};
use tokio::process::{Child, Command};
use tokio::time::Instant;

use crate::evidence;
use crate::link::{Arrival, Link};
use crate::record::{self, End, Finish, Header, Llm, LogCheck, Route};

/// How long the daemon may take to open its socket.
const SOCKET_PATIENCE: Duration = Duration::from_mins(1);
/// The first admission of a root fetches its image.
const ADMIT_WAIT: Duration = Duration::from_mins(15);
/// How long to wait for Hunter's standing YARA grant.
const YARA_PATIENCE: Duration = Duration::from_mins(5);
/// How long the agents may take to connect.
const ONLINE_PATIENCE: Duration = Duration::from_mins(3);
/// How long the ransomware run and the integrity check may take.
const DETONATE_WAIT: Duration = Duration::from_mins(3);
/// Events still arriving after the agents exit.
const DRAIN: Duration = Duration::from_secs(2);
/// The roots the strata run on by default (Forensics on Alpine, the rest on Debian).
const ROOTS: [&str; 2] = ["debian", "alpine"];
/// The daemon's status line for a tool request that waits for a commander.
const PENDING_TOOL: &str = "waiting for a commander's signature on ";

/// The binaries a run uses (snapshots taken when the eval starts).
#[derive(Debug, Clone)]
pub(crate) struct Bins {
    /// `cleanroomd`.
    pub(crate) daemon: PathBuf,
    /// `cleanroom-agents`.
    pub(crate) agents: PathBuf,
    /// The static `cleanroom-ransom`.
    pub(crate) ransom: PathBuf,
}

/// Everything shared by the runs of one eval.
#[derive(Debug)]
pub(crate) struct Plan {
    /// Repository root: `scenario/`, `roots/` and `flake.lock`.
    pub(crate) repo: PathBuf,
    /// Scratch root: per-run state, sockets and logs, and the shared OCI store.
    pub(crate) work: PathBuf,
    /// Results directory.
    pub(crate) out: PathBuf,
    /// Root of the per-run model recordings.
    pub(crate) llm_cache: PathBuf,
    /// The binaries.
    pub(crate) bins: Bins,
    /// Hosted only, or with the local route.
    pub(crate) route: Route,
    /// Live or replayed model answers.
    pub(crate) llm: Llm,
    /// Extra agent environment (`local.env` for the local route).
    pub(crate) agent_env: Vec<(String, String)>,
    /// `--max-steps` for the agents.
    pub(crate) max_steps: u32,
    /// Longest a run may take after the detonation.
    pub(crate) run_timeout: Duration,
    /// Keep each run's state directory and logs.
    pub(crate) keep_state: bool,
}

/// One cell of the eval at one repetition.
#[derive(Debug, Clone)]
pub(crate) struct Case {
    /// Variant name.
    pub(crate) variant: String,
    /// The `detonate` scenario.
    pub(crate) scenario: String,
    /// Agent guardrails at start.
    pub(crate) guardrails: bool,
    /// 1-based repetition.
    pub(crate) repetition: u32,
}

impl Case {
    /// Run id, for example `baseline-off-hosted-1`.
    pub(crate) fn id(&self, route: Route) -> String {
        format!(
            "{}-{}-{}-{}",
            self.variant,
            on_off(self.guardrails),
            route.name(),
            self.repetition
        )
    }
}

/// Where one run keeps its files.
#[derive(Debug)]
struct Paths {
    /// The run's scratch directory.
    dir: PathBuf,
    /// The daemon's socket.
    socket: PathBuf,
    /// The daemon's state.
    state: PathBuf,
    /// `XDG_STATE_HOME` for the daemon and the agents (keys).
    xdg_state: PathBuf,
    /// The daemon's output.
    daemon_log: PathBuf,
    /// The agents' output.
    agents_log: PathBuf,
}

impl Paths {
    /// The layout under `dir`.
    fn new(dir: PathBuf) -> Self {
        Self {
            socket: dir.join("cleanroomd.sock"),
            state: dir.join("state"),
            xdg_state: dir.join("xdg-state"),
            daemon_log: dir.join("cleanroomd.log"),
            agents_log: dir.join("agents.log"),
            dir,
        }
    }
}

/// What one run produced before it is written out.
#[derive(Debug)]
struct Outcome {
    /// Every event and its arrival time.
    events: Vec<Arrival>,
    /// When the detonate request went out, if it did.
    detonated: Option<Instant>,
    /// Whether Hunter's YARA grant was in place before the detonation.
    yara_ready: bool,
    /// Measurements after the run.
    end: End,
}

/// The path of a finished run's file, if the run already has one.
pub(crate) fn finished(plan: &Plan, case: &Case) -> Option<PathBuf> {
    let path = run_file(plan, case);
    record::read_run(&path).is_ok().then_some(path)
}

/// The run file for `case`.
fn run_file(plan: &Plan, case: &Case) -> PathBuf {
    plan.out
        .join("runs")
        .join(format!("{}.jsonl", case.id(plan.route)))
}

/// Run `case` and write its run file.
///
/// # Errors
/// Fails when the stack cannot be brought up (daemon, admission, agents): the eval cannot
/// measure anything then. A run that fails later (detonation, agents crash, timeout) is
/// recorded with its finish instead.
pub(crate) async fn run(plan: &Plan, case: &Case) -> Result<PathBuf> {
    let id = case.id(plan.route);
    let paths = Paths::new(plan.work.join("runs").join(&id));
    prepare(&plan.work, &paths)?;
    let started_at = now();
    let mut daemon = spawn_daemon(plan, &paths)?;
    let outcome = Box::pin(drive(plan, case, &paths)).await;
    if let Err(error) = daemon.start_kill() {
        tracing::warn!("cannot stop cleanroomd: {error}");
    }
    if let Err(error) = daemon.wait().await {
        tracing::warn!("cannot reap cleanroomd: {error}");
    }
    let outcome = outcome?;
    let t0 = outcome
        .detonated
        .or_else(|| outcome.events.first().map(|arrival| arrival.at))
        .unwrap_or_else(Instant::now);
    let header = Header {
        run: id.clone(),
        variant: case.variant.clone(),
        scenario: case.scenario.clone(),
        guardrails: case.guardrails,
        repetition: case.repetition,
        route: plan.route,
        llm: plan.llm,
        max_steps: plan.max_steps,
        started_at,
        yara_ready: outcome.yara_ready,
    };
    let events = outcome
        .events
        .into_iter()
        .map(|arrival| (relative(arrival.at, t0), arrival.event))
        .collect();
    let path = run_file(plan, case);
    fs::create_dir_all(plan.out.join("runs"))
        .with_context(|| format!("cannot create {}", plan.out.display()))?;
    if outcome.end.finish != Finish::Finished || plan.keep_state {
        keep_logs(plan, &paths, &id)?;
    }
    record::write_run(&path, header, events, outcome.end)?;
    if !plan.keep_state {
        remove_tree(&paths.dir)?;
    }
    Ok(path)
}

/// Bring the stack up, detonate, collect, and measure.
///
/// # Errors
/// Fails when the daemon, the admission or the agents cannot be brought up.
async fn drive(plan: &Plan, case: &Case, paths: &Paths) -> Result<Outcome> {
    let mut link = Link::open(&paths.socket, SOCKET_PATIENCE).await?;
    admit(&mut link).await?;
    let yara_ready = wait_for_yara(&paths.state.join("receipts.ndjson")).await;
    if !yara_ready {
        tracing::warn!("hunter's standing yara grant is not in place; the run continues");
    }
    let mut agents = spawn_agents(plan, case, paths)?;
    let mut events = Vec::new();
    wait_online(&mut link, &mut events, &mut agents).await?;
    let detonated = Instant::now();
    let request = CoreRequest::Detonate {
        scenario: case.scenario.clone(),
    };
    let finish = match link.request(request, DETONATE_WAIT).await? {
        CoreResponse::Ok => None,
        CoreResponse::Error { message } => Some(Finish::DetonateFailed { error: message }),
        CoreResponse::Exec(_)
        | CoreResponse::Tool { .. }
        | CoreResponse::Admitted { .. }
        | CoreResponse::AdmitRejected { .. }
        | CoreResponse::LogVerified { .. } => Some(Finish::DetonateFailed {
            error: "cleanroomd answered detonate with something else".to_owned(),
        }),
    };
    let before = evidence::fingerprint(&paths.state)?;
    let finish = if let Some(failed) = finish {
        stop(&mut agents).await;
        failed
    } else {
        let deadline = detonated + plan.run_timeout;
        collect(&mut link, &mut events, &mut agents, deadline).await?
    };
    let ended = Instant::now();
    let log = match link.verify_log().await {
        Ok((entries, first_break)) => Some(LogCheck {
            entries,
            first_break,
        }),
        Err(error) => {
            tracing::warn!("verify_log failed: {error:#}");
            None
        }
    };
    drain(&mut link, &mut events).await?;
    let after = evidence::fingerprint(&paths.state)?;
    let (model_retries, rate_limited) = evidence::retries(&paths.agents_log)?;
    let end = End {
        t_ms: relative(ended, detonated),
        finish,
        log,
        receipts: evidence::receipts(&paths.state.join("receipts.ndjson"))?,
        evidence_changed: evidence::changes(&before, &after),
        model_retries,
        rate_limited,
    };
    Ok(Outcome {
        events,
        detonated: Some(detonated),
        yara_ready,
        end,
    })
}

/// Admit every root the strata run on, before any agent needs one.
///
/// # Errors
/// Fails unless the daemon answers `admitted` for each.
async fn admit(link: &mut Link) -> Result<()> {
    for root in ROOTS {
        let request = CoreRequest::Admit {
            root: root.to_owned(),
        };
        match link.request(request, ADMIT_WAIT).await? {
            CoreResponse::Admitted { .. } => {}
            CoreResponse::AdmitRejected { layer, .. } => {
                bail!("{root} was rejected at layer {layer}")
            }
            CoreResponse::Error { message } => bail!("admitting {root}: {message}"),
            CoreResponse::Exec(_)
            | CoreResponse::Tool { .. }
            | CoreResponse::LogVerified { .. }
            | CoreResponse::Ok => bail!("cleanroomd answered admit with something else"),
        }
    }
    Ok(())
}

/// Wait until `receipts` records Hunter's standing YARA grant; false if it never does.
async fn wait_for_yara(receipts: &Path) -> bool {
    let deadline = Instant::now() + YARA_PATIENCE;
    loop {
        let granted =
            fs::read_to_string(receipts).is_ok_and(|log| log.contains("\"standing-hunter-yara\""));
        if granted {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Record events until the agents announce they are online.
///
/// # Errors
/// Fails if the agents exit or stay silent, or the connection closes.
async fn wait_online(link: &mut Link, events: &mut Vec<Arrival>, agents: &mut Child) -> Result<()> {
    let deadline = Instant::now() + ONLINE_PATIENCE;
    loop {
        tokio::select! {
            status = agents.wait() => {
                let status = status.context("cannot wait for the agents")?;
                bail!("the agents exited before coming online ({status}); see their log");
            }
            arrival = link.next_event(deadline) => {
                let Some(arrival) = arrival? else {
                    stop(agents).await;
                    bail!("the agents did not come online within {} s", ONLINE_PATIENCE.as_secs());
                };
                let online = matches!(
                    &arrival.event.body,
                    BusMessage { from: Principal::Agent { .. }, body: BusBody::Status { text }, .. }
                        if text.contains("agents online on")
                );
                events.push(arrival);
                if online {
                    return Ok(());
                }
            }
        }
    }
}

/// Record events, answering for the commander, until the agents exit or `deadline` passes.
///
/// # Errors
/// Fails if the connection to the daemon closes.
async fn collect(
    link: &mut Link,
    events: &mut Vec<Arrival>,
    agents: &mut Child,
    deadline: Instant,
) -> Result<Finish> {
    loop {
        tokio::select! {
            status = agents.wait() => {
                return Ok(match status {
                    Ok(status) if status.success() => Finish::Finished,
                    Ok(status) => Finish::AgentsFailed { code: status.code() },
                    Err(error) => {
                        tracing::warn!("cannot wait for the agents: {error}");
                        Finish::AgentsFailed { code: None }
                    }
                });
            }
            arrival = link.next_event(deadline) => {
                let Some(arrival) = arrival? else {
                    stop(agents).await;
                    return Ok(Finish::TimedOut);
                };
                if let Some(subject) = awaits_commander(&arrival.event) {
                    match link.reject(&subject).await {
                        Ok(CoreResponse::Ok) => tracing::info!(subject, "rejected as the commander"),
                        Ok(_) => tracing::warn!(subject, "the daemon did not accept the rejection"),
                        Err(error) => tracing::warn!(subject, "cannot reject: {error:#}"),
                    }
                }
                events.push(arrival);
            }
        }
    }
}

/// The proposal or pending tool request in `event` that waits for the commander, if any.
fn awaits_commander(event: &Signed<BusMessage>) -> Option<String> {
    match &event.body.body {
        BusBody::Proposal { proposal_id, .. } => Some(proposal_id.clone()),
        BusBody::Status { text } if event.body.from == Principal::System => text
            .split_once(PENDING_TOOL)
            .map(|(_, id)| id.trim().to_owned())
            .filter(|id| !id.is_empty()),
        BusBody::Status { .. }
        | BusBody::Chat { .. }
        | BusBody::Finding { .. }
        | BusBody::Approval { .. }
        | BusBody::ToolRequest(_)
        | BusBody::ToolDecision { .. }
        | BusBody::Trace { .. }
        | BusBody::Refusal { .. }
        | BusBody::Counters { .. }
        | BusBody::SafetyVerdict { .. }
        | BusBody::Route { .. }
        | BusBody::Scope(_)
        | BusBody::Incident(_)
        | BusBody::Investigate { .. }
        | BusBody::AgentControl { .. }
        | BusBody::Memory(_) => None,
    }
}

/// Record the events still in flight.
///
/// # Errors
/// Fails if the connection closes.
async fn drain(link: &mut Link, events: &mut Vec<Arrival>) -> Result<()> {
    let deadline = Instant::now() + DRAIN;
    while let Some(arrival) = link.next_event(deadline).await? {
        events.push(arrival);
    }
    Ok(())
}

/// Kill a child and reap it.
async fn stop(child: &mut Child) {
    if let Err(error) = child.start_kill() {
        tracing::debug!("cannot kill a child process: {error}");
    }
    if let Err(error) = child.wait().await {
        tracing::debug!("cannot reap a child process: {error}");
    }
}

/// Start `cleanroomd` on the run's socket and state.
///
/// # Errors
/// Fails if the log cannot be created or the daemon cannot be started.
fn spawn_daemon(plan: &Plan, paths: &Paths) -> Result<Child> {
    let log = File::create(&paths.daemon_log)
        .with_context(|| format!("cannot create {}", paths.daemon_log.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("cannot share {}", paths.daemon_log.display()))?;
    Command::new(&plan.bins.daemon)
        .arg("--socket")
        .arg(&paths.socket)
        .arg("--state")
        .arg(&paths.state)
        .arg("--repo")
        .arg(&plan.repo)
        .env("CLEANROOM_RANSOM_BIN", &plan.bins.ransom)
        .env("XDG_STATE_HOME", &paths.xdg_state)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {}", plan.bins.daemon.display()))
}

/// Start `cleanroom-agents run --once` for `case`.
///
/// # Errors
/// Fails if a replay has no recording, or the agents cannot be started.
fn spawn_agents(plan: &Plan, case: &Case, paths: &Paths) -> Result<Child> {
    let recording = plan.llm_cache.join(case.id(plan.route));
    let mode = match plan.llm {
        Llm::Live => "record",
        Llm::Replay if recording.is_dir() => "replay",
        Llm::Replay => bail!("no recording to replay at {}", recording.display()),
    };
    let log = File::create(&paths.agents_log)
        .with_context(|| format!("cannot create {}", paths.agents_log.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("cannot share {}", paths.agents_log.display()))?;
    Command::new(&plan.bins.agents)
        .args(["run", "--once", "--guardrails", on_off(case.guardrails)])
        .arg("--max-steps")
        .arg(plan.max_steps.to_string())
        .arg("--socket")
        .arg(&paths.socket)
        .envs(plan.agent_env.iter().map(|(key, value)| (key, value)))
        .env("XDG_STATE_HOME", &paths.xdg_state)
        .env("CLEANROOM_LLM_CACHE", mode)
        .env("CLEANROOM_LLM_CACHE_DIR", &recording)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {}", plan.bins.agents.display()))
}

/// A fresh run directory whose daemon state shares the work directory's OCI store.
///
/// # Errors
/// Fails if a directory or the store link cannot be created.
fn prepare(work: &Path, paths: &Paths) -> Result<()> {
    remove_tree(&paths.dir)?;
    let oci = work.join("cache/oci");
    for dir in [&oci, &paths.state.join("store"), &paths.xdg_state] {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let link = paths.state.join("store/oci");
    std::os::unix::fs::symlink(&oci, &link)
        .with_context(|| format!("cannot link {} to {}", link.display(), oci.display()))
}

/// Copy the run's daemon and agent logs into the results.
///
/// # Errors
/// Fails if a log cannot be copied.
fn keep_logs(plan: &Plan, paths: &Paths, id: &str) -> Result<()> {
    let logs = plan.out.join("logs");
    fs::create_dir_all(&logs).with_context(|| format!("cannot create {}", logs.display()))?;
    for (log, name) in [
        (&paths.daemon_log, "cleanroomd"),
        (&paths.agents_log, "agents"),
    ] {
        let target = logs.join(format!("{id}.{name}.log"));
        match fs::copy(log, &target) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("cannot copy {}", log.display()));
            }
        }
    }
    Ok(())
}

/// Remove a directory tree; a missing one is fine.
///
/// # Errors
/// Fails if the tree exists and cannot be removed.
pub(crate) fn remove_tree(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// Milliseconds from `origin` to `at`, negative when `at` is earlier.
fn relative(at: Instant, origin: Instant) -> i64 {
    let millis = |duration: Duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
    at.checked_duration_since(origin)
        .map_or_else(|| -millis(origin.saturating_duration_since(at)), millis)
}

/// The current time, RFC 3339 with seconds.
pub(crate) fn now() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

/// `on` or `off`.
pub(crate) const fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}
