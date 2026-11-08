//! Strata: bubblewrap sandboxes built from a [`Grant`].
//!
//! The admitted root is mounted read-only as `/`, with a fresh `/proc`, `/dev` and `/tmp`. The
//! grant's mounts are bound read-only or read-write; everything else stays out. Every namespace
//! is unshared (so there is no network), all capabilities are dropped, and the environment is
//! cleared. A write to a read-only mount fails in the kernel with `EROFS`; [`classify`] reports
//! that as a denial.

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result};
use cleanroom_proto::{ExecOutcome, Grant, Mount, MountMode, Network, Role};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Command;
use tokio::task::JoinHandle;

use crate::layout::Layout;
use crate::roots::Admitted;
use crate::tools::Granted;

/// Bytes kept per output stream.
pub(crate) const OUTPUT_CAP: usize = 64 * 1024;
/// Longest any command may run, whatever the request asks for.
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_mins(5);
/// How long to wait for output pipes to close after the sandbox has exited.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The victim stratum the scenario runs in.
pub(crate) const VICTIM: &str = "acme-fs";

/// Evidence: the victim's share, as investigators see it.
pub(crate) const EVIDENCE_SHARE: &str = "/evidence/acme-fs";
/// Evidence: the victim's drop box.
pub(crate) const EVIDENCE_DROP: &str = "/evidence/dropbox";
/// Evidence: the victim's logs.
pub(crate) const EVIDENCE_LOGS: &str = "/evidence/logs";
/// YARA rules.
pub(crate) const RULES: &str = "/rules";
/// The role's writable scratch space.
const SCRATCH: &str = "/scratch";
/// The Nix store, for admitted tools.
const NIX_STORE: &str = "/nix/store";
/// The victim's share, as the victim sees it.
pub(crate) const VICTIM_SHARE: &str = "/srv/acme-fs/share";
/// The victim's drop box.
pub(crate) const VICTIM_DROP: &str = "/srv/acme-fs/drop";
/// The victim's logs.
pub(crate) const VICTIM_LOGS: &str = "/srv/acme-fs/logs";
/// Binaries the daemon places into the victim stratum.
pub(crate) const VICTIM_BIN: &str = "/opt/cleanroom/bin";

/// Every mount point a grant uses. bubblewrap cannot create a mount point inside a read-only
/// root, so admission creates these in the unpacked tree before taking its digest.
pub(crate) const MOUNT_POINTS: [&str; 10] = [
    EVIDENCE_SHARE,
    EVIDENCE_DROP,
    EVIDENCE_LOGS,
    RULES,
    SCRATCH,
    NIX_STORE,
    VICTIM_SHARE,
    VICTIM_DROP,
    VICTIM_LOGS,
    VICTIM_BIN,
];

/// Debian's default search path; admitted tools go in front of it.
const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The kernel's message for `EROFS`.
const READ_ONLY: &str = "Read-only file system";

/// The stratum a role's commands run in: the role's own name (the grants table).
pub(crate) const fn stratum_of(role: Role) -> &'static str {
    match role {
        Role::Hunter => "hunter",
        Role::Forensics => "forensics",
        Role::Scribe => "scribe",
        Role::Containment => "containment",
    }
}

/// Why `role` may not run commands in `stratum`, if it may not.
pub(crate) fn refusal(role: Role, stratum: &str) -> Option<String> {
    match role {
        Role::Scribe => Some(
            "scribe has no exec: its stratum has no shell tools, and records go through cleanroomd"
                .to_owned(),
        ),
        Role::Containment => {
            Some("containment has no exec: it has no root and can only propose actions".to_owned())
        }
        Role::Hunter | Role::Forensics if stratum != stratum_of(role) => Some(format!(
            "{} may only run commands in the {} stratum, not {stratum}",
            stratum_of(role),
            stratum_of(role)
        )),
        Role::Hunter | Role::Forensics => None,
    }
}

/// An investigator's grant: evidence and rules read-only, its scratch read-write, the Nix store
/// read-only only when it holds admitted tools, no network.
///
/// # Errors
/// Fails if a host path is not UTF-8.
pub(crate) fn investigator(
    layout: &Layout,
    role: Role,
    root: &Admitted,
    tools: &[Granted],
) -> Result<Grant> {
    let mut mounts = vec![
        mount(&layout.share(), EVIDENCE_SHARE, MountMode::ReadOnly)?,
        mount(&layout.dropbox(), EVIDENCE_DROP, MountMode::ReadOnly)?,
        mount(&layout.logs(), EVIDENCE_LOGS, MountMode::ReadOnly)?,
        mount(&layout.rules(), RULES, MountMode::ReadOnly)?,
        mount(&layout.scratch(role), SCRATCH, MountMode::ReadWrite)?,
    ];
    if !tools.is_empty() {
        mounts.push(mount(Path::new(NIX_STORE), NIX_STORE, MountMode::ReadOnly)?);
    }
    Ok(Grant {
        stratum: stratum_of(role).to_owned(),
        role: Some(role),
        root: root.manifest.clone(),
        mounts,
        network: Network::None,
        tools: tools.iter().map(|tool| tool.name.clone()).collect(),
    })
}

/// The victim's grant: its share, drop box and logs read-write, the daemon's binaries
/// read-only, no network.
///
/// # Errors
/// Fails if a host path is not UTF-8.
pub(crate) fn victim(layout: &Layout, root: &Admitted) -> Result<Grant> {
    Ok(Grant {
        stratum: VICTIM.to_owned(),
        role: None,
        root: root.manifest.clone(),
        mounts: vec![
            mount(&layout.share(), VICTIM_SHARE, MountMode::ReadWrite)?,
            mount(&layout.dropbox(), VICTIM_DROP, MountMode::ReadWrite)?,
            mount(&layout.logs(), VICTIM_LOGS, MountMode::ReadWrite)?,
            mount(&layout.bin(), VICTIM_BIN, MountMode::ReadOnly)?,
        ],
        network: Network::None,
        tools: Vec::new(),
    })
}

/// One bind of a grant.
///
/// # Errors
/// Fails if `host` is not UTF-8.
fn mount(host: &Path, guest: &str, mode: MountMode) -> Result<Mount> {
    let host = host
        .to_str()
        .with_context(|| format!("{} is not a UTF-8 path", host.display()))?;
    Ok(Mount {
        host: host.to_owned(),
        guest: guest.to_owned(),
        mode,
    })
}

/// One command to run in a stratum.
#[derive(Debug)]
pub(crate) struct Launch<'a> {
    /// The admitted root, mounted read-only as `/`.
    pub(crate) rootfs: &'a Path,
    /// What the stratum may touch.
    pub(crate) grant: &'a Grant,
    /// `bin` directories of admitted tools, searched first.
    pub(crate) bins: &'a [PathBuf],
    /// Program and arguments.
    pub(crate) argv: &'a [String],
    /// Kill the sandbox after this long.
    pub(crate) timeout: Duration,
}

/// What a command did.
#[derive(Debug, Default)]
pub(crate) struct Captured {
    /// Exit code; `128 + signal` when killed by a signal; `None` when it never finished.
    pub(crate) code: Option<i32>,
    /// Standard output, at most [`OUTPUT_CAP`] bytes.
    pub(crate) stdout: String,
    /// Standard error, at most [`OUTPUT_CAP`] bytes.
    pub(crate) stderr: String,
    /// Either stream hit the cap.
    pub(crate) truncated: bool,
    /// The timeout killed it.
    pub(crate) timed_out: bool,
}

/// Run `launch` under bubblewrap, capturing capped output and enforcing the timeout.
///
/// # Errors
/// Fails if bubblewrap cannot be started or waited for.
pub(crate) async fn run(launch: &Launch<'_>) -> Result<Captured> {
    let mut child = Command::new("bwrap")
        .args(bwrap_args(launch))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start bwrap (is bubblewrap on PATH?)")?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| tokio::spawn(read_capped(pipe)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(read_capped(pipe)));
    let (status, timed_out) = match tokio::time::timeout(launch.timeout, child.wait()).await {
        Ok(status) => (Some(status.context("cannot wait for bwrap")?), false),
        Err(_elapsed) => {
            if let Err(error) = child.start_kill() {
                tracing::warn!("cannot kill a timed-out stratum: {error}");
            }
            (child.wait().await.ok(), true)
        }
    };
    let (stdout, stdout_cut) = drain(stdout).await;
    let (stderr, stderr_cut) = drain(stderr).await;
    Ok(Captured {
        code: status.and_then(|status| {
            status
                .code()
                .or_else(|| status.signal().map(|signal| 128 + signal))
        }),
        stdout,
        stderr,
        truncated: stdout_cut || stderr_cut,
        timed_out,
    })
}

/// The bubblewrap command line for `launch`.
fn bwrap_args(launch: &Launch<'_>) -> Vec<OsString> {
    let grant = launch.grant;
    let scratch = grant.mounts.iter().any(|mount| mount.guest == SCRATCH);
    let home = if scratch { SCRATCH } else { "/tmp" };
    let mut args: Vec<OsString> = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--hostname",
        grant.stratum.as_str(),
        "--setenv",
        "HOME",
        home,
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "PATH",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(search_path(launch.bins));
    args.push("--ro-bind".into());
    args.push(launch.rootfs.into());
    args.extend(
        ["/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
            .into_iter()
            .map(OsString::from),
    );
    for mount in &grant.mounts {
        let flag = match mount.mode {
            MountMode::ReadOnly => "--ro-bind",
            MountMode::ReadWrite => "--bind",
            // Append-only records are written through cleanroomd, never bound into a stratum.
            MountMode::AppendOnly => continue,
        };
        args.extend([flag, mount.host.as_str(), mount.guest.as_str()].map(OsString::from));
    }
    args.extend(["--chdir", home, "--"].map(OsString::from));
    args.extend(launch.argv.iter().map(OsString::from));
    args
}

/// `PATH` inside the stratum: admitted tools first, then Debian's.
fn search_path(bins: &[PathBuf]) -> OsString {
    let mut path = OsString::new();
    for bin in bins {
        path.push(bin);
        path.push(":");
    }
    path.push(BASE_PATH);
    path
}

/// Kept bytes of one output stream, and whether more was dropped.
type Output = (Vec<u8>, bool);

/// Read a pipe to the end, keeping the first [`OUTPUT_CAP`] bytes.
///
/// # Errors
/// Fails if the pipe cannot be read.
async fn read_capped<R: AsyncRead + Unpin>(mut pipe: R) -> std::io::Result<Output> {
    let mut kept = Vec::new();
    let mut chunk = vec![0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let read = pipe.read(&mut chunk).await?;
        if read == 0 {
            return Ok((kept, truncated));
        }
        let room = OUTPUT_CAP.saturating_sub(kept.len());
        let keep = read.min(room);
        kept.extend_from_slice(chunk.get(..keep).unwrap_or_default());
        truncated |= keep < read;
    }
}

/// Collect a reader task, giving up shortly after the sandbox is gone.
async fn drain(task: Option<JoinHandle<std::io::Result<Output>>>) -> (String, bool) {
    let Some(task) = task else {
        return (String::new(), false);
    };
    let abort = task.abort_handle();
    match tokio::time::timeout(DRAIN_GRACE, task).await {
        Ok(Ok(Ok((bytes, truncated)))) => (String::from_utf8_lossy(&bytes).into_owned(), truncated),
        Ok(Ok(Err(error))) => {
            tracing::warn!("cannot read stratum output: {error}");
            (String::new(), true)
        }
        Ok(Err(error)) => {
            tracing::warn!("stratum output reader failed: {error}");
            (String::new(), true)
        }
        Err(_elapsed) => {
            abort.abort();
            (String::new(), true)
        }
    }
}

/// The outcome of a finished command run by `who`. A command that tried to modify a read-only
/// mount is `denied`: the kernel refused the write with `EROFS`, whatever the exit code.
pub(crate) fn classify(who: &str, captured: &Captured) -> ExecOutcome {
    if captured.timed_out {
        return ExecOutcome::TimedOut;
    }
    if let Some(reason) = read_only_denial(who, &captured.stderr) {
        return ExecOutcome::Denied { reason };
    }
    ExecOutcome::Exited {
        code: captured.code.unwrap_or(-1),
    }
}

/// The denial reason when `stderr` shows a write refused by a read-only mount.
fn read_only_denial(who: &str, stderr: &str) -> Option<String> {
    let refused: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains(READ_ONLY))
        .collect();
    if refused.is_empty() {
        return None;
    }
    let touched = |prefix: &str| refused.iter().any(|line| line.contains(prefix));
    let what = if touched("/evidence") {
        "evidence is"
    } else if touched(RULES) {
        "/rules is"
    } else if touched("/proc") {
        "/proc is"
    } else {
        "the root filesystem is"
    };
    Some(format!("{what} mounted read_only for {who}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finished(code: i32, stderr: &str) -> Captured {
        Captured {
            code: Some(code),
            stderr: stderr.to_owned(),
            ..Captured::default()
        }
    }

    #[test]
    fn evidence_writes_are_denied_with_the_mount_named() {
        let rm = finished(
            1,
            "rm: cannot remove '/evidence/acme-fs/payroll.csv.locked': Read-only file system\n\
             rm: cannot remove '/evidence/dropbox': Read-only file system\n",
        );
        assert_eq!(
            classify("hunter", &rm),
            ExecOutcome::Denied {
                reason: "evidence is mounted read_only for hunter".into()
            },
            "rm -rf /evidence/* is a denial"
        );
        let redirect = finished(
            2,
            "sh: 1: cannot create /evidence/x: Read-only file system\n",
        );
        assert!(
            matches!(classify("forensics", &redirect), ExecOutcome::Denied { reason } if reason == "evidence is mounted read_only for forensics"),
            "a shell redirect into evidence is a denial"
        );
        let masked = finished(
            0,
            "rm: cannot remove '/evidence/logs/auth.log': Read-only file system\n",
        );
        assert!(
            matches!(classify("hunter", &masked), ExecOutcome::Denied { .. }),
            "the kernel refused the write even though the shell exited 0"
        );
    }

    #[test]
    fn other_read_only_paths_are_named() {
        let root = finished(1, "touch: cannot touch '/etc/x': Read-only file system\n");
        assert_eq!(
            classify("hunter", &root),
            ExecOutcome::Denied {
                reason: "the root filesystem is mounted read_only for hunter".into()
            },
            "writes to the root are denials too"
        );
        let rules = finished(
            1,
            "rm: cannot remove '/rules/x.yar': Read-only file system\n",
        );
        assert!(
            matches!(classify("hunter", &rules), ExecOutcome::Denied { reason } if reason.starts_with("/rules")),
            "rules are named"
        );
    }

    #[test]
    fn plain_failures_and_timeouts_are_not_denials() {
        let grep = finished(1, "");
        assert_eq!(
            classify("hunter", &grep),
            ExecOutcome::Exited { code: 1 },
            "grep without matches"
        );
        let missing = finished(
            2,
            "ls: cannot access '/evidence/nope': No such file or directory\n",
        );
        assert_eq!(
            classify("hunter", &missing),
            ExecOutcome::Exited { code: 2 },
            "a missing file is an ordinary failure"
        );
        let slow = Captured {
            timed_out: true,
            stderr: "Read-only file system".into(),
            ..Captured::default()
        };
        assert_eq!(
            classify("hunter", &slow),
            ExecOutcome::TimedOut,
            "the timeout wins"
        );
    }
}
