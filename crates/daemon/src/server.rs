//! The Unix socket: one task per client, newline-delimited JSON envelopes, `hello` first.
//!
//! Each client gets a writer task fed by its outbox, so bus events, replayed state and
//! responses never interleave mid-line. Requests run concurrently and answer with their id.

use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{CoreResponse, Envelope, Frame, WIRE_VERSION};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::bus::Outbox;
use crate::daemon::{Daemon, Peer};
use crate::layout::private_dir;

/// Longest line accepted from a client.
const MAX_LINE: usize = 4 * 1024 * 1024;
/// Lines queued per client before it counts as stuck.
const OUTBOX_CAPACITY: usize = 8 * 1024;

/// Bind the socket (mode 0600; a new parent directory gets 0700), replacing a stale one.
///
/// # Errors
/// Fails if another daemon is listening, the path holds something other than a socket, or the
/// socket cannot be bound.
pub(crate) fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("cleanroomd is already listening on {}", path.display());
            }
            fs::remove_file(path)
                .with_context(|| format!("cannot remove the stale socket {}", path.display()))?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()));
        }
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot bind {}", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("cannot restrict {}", path.display()))?;
    Ok(listener)
}

/// Accept clients until SIGINT or SIGTERM, then remove the socket.
///
/// # Errors
/// Fails if the signal handlers cannot be installed.
pub(crate) async fn serve(daemon: Arc<Daemon>, listener: UnixListener, path: &Path) -> Result<()> {
    let mut terminate = signal(SignalKind::terminate()).context("cannot listen for SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("cannot listen for SIGINT")?;
    tracing::info!(socket = %path.display(), "cleanroomd is listening");
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(client(Arc::clone(&daemon), stream));
                }
                Err(error) => tracing::warn!("cannot accept a client: {error}"),
            },
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    tracing::info!("shutting down");
    if let Err(error) = fs::remove_file(path) {
        tracing::warn!(socket = %path.display(), "cannot remove the socket: {error}");
    }
    Ok(())
}

/// Serve one client until it disconnects.
async fn client(daemon: Arc<Daemon>, stream: UnixStream) {
    let (read, write) = stream.into_split();
    let (outbox, queue) = mpsc::channel(OUTBOX_CAPACITY);
    let writer = tokio::spawn(write_lines(write, queue));
    let mut reader = BufReader::new(read);
    match greet(&mut reader, &outbox).await {
        Ok(Some((peer, audiences))) => {
            tracing::info!(peer = %peer.name(), "client connected");
            let subscription = daemon.subscribe(audiences, outbox.clone());
            converse(&daemon, &Arc::new(peer), &mut reader, &outbox).await;
            daemon.unsubscribe(subscription);
        }
        Ok(None) => {}
        Err(error) => tracing::warn!("refusing a client: {error:#}"),
    }
    drop(outbox);
    if let Err(error) = writer.await {
        tracing::warn!("a client writer failed: {error}");
    }
}

/// Read the first frame, which must be a valid `hello`.
///
/// # Errors
/// Fails if the first frame is unreadable, not `hello`, or names an unacceptable principal.
async fn greet(
    reader: &mut BufReader<OwnedReadHalf>,
    outbox: &Outbox,
) -> Result<Option<(Peer, Vec<cleanroom_proto::Audience>)>> {
    let Some(line) = read_line(reader).await? else {
        return Ok(None);
    };
    let envelope: Envelope =
        serde_json::from_slice(&line).context("the first line is not an envelope")?;
    match envelope.frame {
        Frame::Hello {
            principal,
            public_key,
            subscribe,
        } => Ok(Some((Peer::new(principal, &public_key)?, subscribe))),
        Frame::Request { id, .. } => {
            let refusal = CoreResponse::Error {
                message: "say hello first".to_owned(),
            };
            respond(outbox, id, refusal).await;
            bail!("the first frame was a request, not hello")
        }
        Frame::Publish(_) | Frame::Event(_) | Frame::Response { .. } => {
            bail!("the first frame was not hello")
        }
    }
}

/// Handle frames after `hello` until the client disconnects.
async fn converse(
    daemon: &Arc<Daemon>,
    peer: &Arc<Peer>,
    reader: &mut BufReader<OwnedReadHalf>,
    outbox: &Outbox,
) {
    loop {
        let line = match read_line(reader).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(peer = %peer.name(), "dropping the client: {error:#}");
                break;
            }
        };
        let envelope: Envelope = match serde_json::from_slice(&line) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::warn!(peer = %peer.name(), "ignoring an unreadable frame: {error}");
                continue;
            }
        };
        if envelope.v != WIRE_VERSION {
            tracing::warn!(peer = %peer.name(), version = envelope.v, "ignoring a frame of another wire version");
            continue;
        }
        match envelope.frame {
            Frame::Publish(signed) => daemon.accept_publish(peer, signed),
            Frame::Request { id, request } => {
                let daemon = Arc::clone(daemon);
                let peer = Arc::clone(peer);
                let outbox = outbox.clone();
                tokio::spawn(async move {
                    let response = Box::pin(daemon.handle(&peer, request)).await;
                    respond(&outbox, id, response).await;
                });
            }
            Frame::Hello { .. } | Frame::Event(_) | Frame::Response { .. } => {
                tracing::warn!(peer = %peer.name(), "ignoring a daemon-side or repeated frame");
            }
        }
    }
}

/// Queue a response line.
async fn respond(outbox: &Outbox, id: u64, response: CoreResponse) {
    let envelope = Envelope {
        v: WIRE_VERSION,
        frame: Frame::Response { id, response },
    };
    match serde_json::to_string(&envelope) {
        Ok(mut line) => {
            line.push('\n');
            if outbox.send(line.into()).await.is_err() {
                tracing::debug!(id, "the client left before its response");
            }
        }
        Err(error) => tracing::error!(id, "cannot encode a response: {error}"),
    }
}

/// Read one line (without the newline); `None` at end of stream.
///
/// # Errors
/// Fails on a read error or a line longer than [`MAX_LINE`].
async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> Result<Option<Vec<u8>>> {
    loop {
        let mut line = Vec::new();
        let limit = u64::try_from(MAX_LINE)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let read = (&mut *reader)
            .take(limit)
            .read_until(b'\n', &mut line)
            .await
            .context("cannot read from the client")?;
        if read == 0 {
            return Ok(None);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        } else if line.len() > MAX_LINE {
            bail!("a line is longer than {MAX_LINE} bytes");
        }
        if !line.iter().all(u8::is_ascii_whitespace) {
            return Ok(Some(line));
        }
    }
}

/// Write queued lines to the client until every sender is gone or the client stops reading.
async fn write_lines(mut writer: OwnedWriteHalf, mut queue: mpsc::Receiver<Arc<str>>) {
    while let Some(line) = queue.recv().await {
        if let Err(error) = writer.write_all(line.as_bytes()).await {
            tracing::debug!("a client stopped reading: {error}");
            return;
        }
    }
    if let Err(error) = writer.shutdown().await {
        tracing::debug!("cannot close a client connection: {error}");
    }
}
