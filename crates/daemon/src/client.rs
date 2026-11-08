//! One-shot client commands that talk to a running cleanroomd over its socket.

use std::io::{self, ErrorKind, Write as _};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{generate_key, key_id};
use cleanroom_proto::{CoreRequest, CoreResponse, Envelope, Frame, Principal, WIRE_VERSION};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::time::Instant;

/// How long to wait for the daemon's socket to accept connections.
const CONNECT_PATIENCE: Duration = Duration::from_secs(30);
/// How long an admission may take; the first one fetches the image.
const ADMIT_WAIT: Duration = Duration::from_mins(10);

/// `cleanroomd admit <root>`: prints the verdict; exit 0 when admitted, 1 when rejected.
///
/// # Errors
/// Fails if the daemon is unreachable, hangs up, or answers with an error.
pub(crate) async fn admit(socket: &Path, root: &str) -> Result<ExitCode> {
    let request = CoreRequest::Admit {
        root: root.to_owned(),
    };
    let (line, code) = match ask(socket, request, ADMIT_WAIT).await? {
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
        CoreResponse::Error { message } => bail!("cleanroomd: {message}"),
        CoreResponse::Exec(_)
        | CoreResponse::Tool { .. }
        | CoreResponse::LogVerified { .. }
        | CoreResponse::Ok => bail!("cleanroomd answered admit with something else"),
    };
    writeln!(io::stdout().lock(), "{line}").context("cannot write to stdout")?;
    Ok(code)
}

/// Connect as an ephemeral human principal, send one request, and wait for its response.
///
/// # Errors
/// Fails if the socket cannot be reached, the connection breaks, or no answer comes in time.
async fn ask(socket: &Path, request: CoreRequest, wait: Duration) -> Result<CoreResponse> {
    let stream = connect(socket).await?;
    let (reader, mut writer) = stream.into_split();
    let key = generate_key().context("cannot generate a session key")?;
    let public = key.verifying_key();
    let frames = [
        Frame::Hello {
            principal: Principal::Human {
                key_id: key_id(&public),
            },
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
