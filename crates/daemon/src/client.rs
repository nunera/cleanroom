//! One-shot client commands that talk to a running cleanroomd over its socket.
//!
//! Human commands connect with a fresh session key (any human key on the 0600 socket may do
//! these); `run` connects as the stratum's agent, so the daemon applies that agent's grant
//! exactly as it does for the Nemotron team.

use std::io::{self, ErrorKind, Write as _};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{generate_key, key_id};
use cleanroom_proto::{
    CoreRequest, CoreResponse, Envelope, ExecOutcome, ExecRequest, Frame, Principal, Role,
    WIRE_VERSION,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::time::Instant;

/// How long to wait for the daemon's socket to accept connections.
const CONNECT_PATIENCE: Duration = Duration::from_secs(30);
/// How long an admission may take; the first one fetches the image.
const ADMIT_WAIT: Duration = Duration::from_mins(10);
/// How long the quick operations (verify, reset, tamper) may take.
const QUICK_WAIT: Duration = Duration::from_mins(1);
/// How long a detonation may take, including the root admission before it.
const DETONATE_WAIT: Duration = Duration::from_mins(12);

/// `cleanroomd admit <root>`: prints the verdict; exit 0 when admitted, 1 when rejected.
///
/// # Errors
/// Fails if the daemon is unreachable, hangs up, or answers with an error.
pub(crate) async fn admit(socket: &Path, root: &str) -> Result<ExitCode> {
    let request = CoreRequest::Admit {
        root: root.to_owned(),
    };
    let (line, code) = match ask(socket, None, request, ADMIT_WAIT).await? {
        CoreResponse::Admitted { root, manifest } => {
            (format!("admitted {root} {manifest}"), ExitCode::SUCCESS)
        }
        CoreResponse::AdmitRejected {
            root,
            layer,
            expected,
            actual,
        } => (
            format!("rejected {root} layer={layer} expected={expected} actual={actual}"),
            ExitCode::from(1),
        ),
        other => return unexpected("admit", other),
    };
    say(&line)?;
    Ok(code)
}

/// `cleanroomd verify`: check every receipt's signature and the chain; exit 0 when intact.
///
/// # Errors
/// Fails if the daemon is unreachable or answers with an error.
pub(crate) async fn verify(socket: &Path) -> Result<ExitCode> {
    match ask(socket, None, CoreRequest::VerifyLog, QUICK_WAIT).await? {
        CoreResponse::LogVerified {
            entries,
            first_break,
        } => {
            let (line, code) = verified(entries, first_break);
            say(&line)?;
            Ok(ExitCode::from(code))
        }
        other => unexpected("verify", other),
    }
}

/// `cleanroomd reset`, `detonate` or `tamper`: an operation that answers `ok`.
///
/// # Errors
/// Fails if the daemon is unreachable or answers with an error.
pub(crate) async fn simple(socket: &Path, request: CoreRequest, done: &str) -> Result<ExitCode> {
    let name = op_label(&request);
    let wait = if matches!(request, CoreRequest::Detonate { .. }) {
        DETONATE_WAIT
    } else {
        QUICK_WAIT
    };
    let started = Instant::now();
    match ask(socket, None, request, wait).await? {
        CoreResponse::Ok => {
            say(&format!("{done} ({} ms)", started.elapsed().as_millis()))?;
            Ok(ExitCode::SUCCESS)
        }
        other => unexpected(name, other),
    }
}

/// `cleanroomd run <stratum> -- <argv>`: run a command as that stratum's agent, under its
/// grant. Prints the command's output and exits with its code, 124 on timeout, or 126 when
/// the grant denies it.
///
/// # Errors
/// Fails for a stratum that is not an agent's, or if the daemon is unreachable or answers with
/// an error.
pub(crate) async fn run(
    socket: &Path,
    stratum: &str,
    argv: Vec<String>,
    timeout: Duration,
) -> Result<ExitCode> {
    let role = role_of(stratum)?;
    let request = CoreRequest::Exec(ExecRequest {
        from: role,
        stratum: stratum.to_owned(),
        argv,
        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
    });
    let wait = timeout + QUICK_WAIT;
    let CoreResponse::Exec(result) = ask(socket, Some(role), request, wait).await? else {
        bail!("cleanroomd answered run with something else");
    };
    io::stdout()
        .lock()
        .write_all(result.stdout.as_bytes())
        .context("cannot write to stdout")?;
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(result.stderr.as_bytes())
        .context("cannot write to stderr")?;
    let note = match &result.outcome {
        ExecOutcome::Exited { .. } => None,
        ExecOutcome::TimedOut => Some("timed out".to_owned()),
        ExecOutcome::Denied { reason } => Some(format!("denied by the {stratum} grant: {reason}")),
    };
    if let Some(note) = note {
        writeln!(
            stderr,
            "cleanroomd: {note} (receipt #{})",
            result.receipt_seq
        )
        .context("cannot write to stderr")?;
    }
    Ok(ExitCode::from(exec_exit(&result.outcome)))
}

/// The line and exit code for a `verify_log` answer.
fn verified(entries: u64, first_break: Option<u64>) -> (String, u8) {
    match first_break {
        None => (
            format!("receipt log verified: {entries} receipts, chain intact"),
            0,
        ),
        Some(entry) => (
            format!("receipt log BROKEN at receipt {entry} of {entries}"),
            1,
        ),
    }
}

/// `run`'s exit code: the command's own (clamped to 0–255), 124 on timeout, 126 when denied.
fn exec_exit(outcome: &ExecOutcome) -> u8 {
    match outcome {
        ExecOutcome::Exited { code } => u8::try_from(*code).unwrap_or(u8::MAX),
        ExecOutcome::TimedOut => 124,
        ExecOutcome::Denied { .. } => 126,
    }
}

/// The agent whose stratum `stratum` is.
///
/// # Errors
/// Fails for anything but an agent stratum.
fn role_of(stratum: &str) -> Result<Role> {
    match stratum {
        "hunter" => Ok(Role::Hunter),
        "forensics" => Ok(Role::Forensics),
        "scribe" => Ok(Role::Scribe),
        "containment" => Ok(Role::Containment),
        other => {
            bail!("`{other}` is not an agent stratum; use hunter, forensics, scribe or containment")
        }
    }
}

/// The op name, for messages.
const fn op_label(request: &CoreRequest) -> &'static str {
    match request {
        CoreRequest::Reset => "reset",
        CoreRequest::Detonate { .. } => "detonate",
        CoreRequest::Tamper { .. } => "tamper",
        CoreRequest::Exec(_)
        | CoreRequest::RequestTool(_)
        | CoreRequest::Approve(_)
        | CoreRequest::Enroll(_)
        | CoreRequest::Revoke(_)
        | CoreRequest::Admit { .. }
        | CoreRequest::VerifyLog => "request",
    }
}

/// Turn an answer the command didn't expect into an error.
///
/// # Errors
/// Always.
fn unexpected<T>(op: &str, response: CoreResponse) -> Result<T> {
    match response {
        CoreResponse::Error { message } => bail!("cleanroomd: {message}"),
        CoreResponse::Exec(_)
        | CoreResponse::Tool { .. }
        | CoreResponse::Admitted { .. }
        | CoreResponse::AdmitRejected { .. }
        | CoreResponse::LogVerified { .. }
        | CoreResponse::Ok => bail!("cleanroomd answered {op} with something else"),
    }
}

/// Print one line to stdout.
///
/// # Errors
/// Fails if stdout is closed.
fn say(line: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{line}").context("cannot write to stdout")
}

/// Connect as a fresh human session key, or as `agent`, send one request, and wait for its
/// response.
///
/// # Errors
/// Fails if the socket cannot be reached, the connection breaks, or no answer comes in time.
async fn ask(
    socket: &Path,
    agent: Option<Role>,
    request: CoreRequest,
    wait: Duration,
) -> Result<CoreResponse> {
    let stream = connect(socket).await?;
    let (reader, mut writer) = stream.into_split();
    let key = generate_key().context("cannot generate a session key")?;
    let public = key.verifying_key();
    let principal = match agent {
        Some(role) => Principal::Agent { role },
        None => Principal::Human {
            key_id: key_id(&public),
        },
    };
    let frames = [
        Frame::Hello {
            principal,
            public_key: hex::encode(public.as_bytes()),
            subscribe: Vec::new(),
        },
        Frame::Request { id: 1, request },
    ];
    for frame in frames {
        let mut line = serde_json::to_string(&Envelope {
            v: WIRE_VERSION,
            frame,
        })
        .context("cannot encode a frame")?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .await
            .context("cannot write to cleanroomd")?;
    }
    let mut lines = BufReader::new(reader).lines();
    let answer = async {
        while let Some(line) = lines
            .next_line()
            .await
            .context("cannot read from cleanroomd")?
        {
            if let Ok(Envelope {
                frame: Frame::Response { id: 1, response },
                ..
            }) = serde_json::from_str(&line)
            {
                return Ok(response);
            }
        }
        bail!("cleanroomd closed the connection without answering")
    };
    tokio::time::timeout(wait, answer)
        .await
        .with_context(|| format!("cleanroomd did not answer within {} s", wait.as_secs()))?
}

/// Connect, retrying while the socket does not exist yet or refuses connections.
///
/// # Errors
/// Fails on any other error, or when the patience runs out.
async fn connect(socket: &Path) -> Result<UnixStream> {
    let deadline = Instant::now() + CONNECT_PATIENCE;
    loop {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot connect to cleanroomd at {}", socket.display())
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_exits_zero_only_for_an_intact_chain() {
        let (line, code) = verified(32, None);
        assert_eq!(code, 0, "intact");
        assert!(
            line.contains("32 receipts") && line.contains("intact"),
            "{line}"
        );
        let (line, code) = verified(32, Some(7));
        assert_eq!(code, 1, "a broken chain fails scripts");
        assert!(line.contains("BROKEN") && line.contains('7'), "{line}");
    }

    #[test]
    fn run_exits_like_the_command_or_names_the_block() {
        assert_eq!(exec_exit(&ExecOutcome::Exited { code: 0 }), 0);
        assert_eq!(
            exec_exit(&ExecOutcome::Exited { code: 2 }),
            2,
            "grep's no-match code passes through"
        );
        assert_eq!(
            exec_exit(&ExecOutcome::Exited { code: 137 }),
            137,
            "killed by a signal"
        );
        assert_eq!(exec_exit(&ExecOutcome::TimedOut), 124, "timeout(1)'s code");
        let denied = ExecOutcome::Denied {
            reason: "evidence is mounted read_only for hunter".to_owned(),
        };
        assert_eq!(exec_exit(&denied), 126, "blocked by the grant");
        assert_eq!(
            exec_exit(&ExecOutcome::Exited { code: -1 }),
            255,
            "out of range maps to 255"
        );
    }

    #[test]
    fn run_takes_an_agent_stratum() {
        assert_eq!(role_of("hunter").ok(), Some(Role::Hunter));
        assert_eq!(role_of("forensics").ok(), Some(Role::Forensics));
        let error = role_of("acme-fs").expect_err("the victim is not an agent stratum");
        assert!(
            format!("{error:#}").contains("hunter"),
            "names the choices: {error:#}"
        );
    }
}
