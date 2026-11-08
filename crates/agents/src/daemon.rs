//! Async client for the `cleanroomd` Unix socket: newline-delimited JSON [`Envelope`]s,
//! request/response correlation by id, bus events, and signed publishes.
//!
//! The runner opens one connection per agent role. Each says `hello` with that role's public
//! key, so the daemon attributes every exec and publish to the role and applies its grant.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::sign;
use cleanroom_proto::{
    Audience, BusBody, BusMessage, CoreRequest, CoreResponse, Envelope, Frame, Principal, Role,
    Signed, Timestamp, WIRE_VERSION, domain,
};
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::roles;

/// Requests waiting for their response, by id.
type Pending = Mutex<HashMap<u64, oneshot::Sender<CoreResponse>>>;

/// What the connections hand to the runner.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A bus event; the daemon already checked its signature.
    Event(Box<Signed<BusMessage>>),
    /// A connection ended.
    Closed {
        /// Whose connection.
        role: Role,
        /// Why.
        reason: String,
    },
}

/// One `cleanroomd` connection speaking for one role.
#[derive(Debug)]
pub(crate) struct Connection {
    /// The role this connection speaks for.
    role: Role,
    /// The role's signing key.
    key: SigningKey,
    /// Write half; one frame at a time.
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    /// Requests waiting for responses.
    pending: Arc<Pending>,
    /// Next request id.
    next_request: AtomicU64,
    /// Next bus message number.
    next_message: AtomicU64,
    /// Distinguishes this process's message ids from earlier runs.
    session: String,
}

impl Connection {
    /// Connect (waiting up to `patience` for the socket to appear), say hello, start the reader.
    ///
    /// # Errors
    /// Fails if the socket cannot be reached in time or the hello cannot be written.
    pub(crate) async fn open(
        socket: &Path,
        role: Role,
        key: SigningKey,
        inbound: mpsc::Sender<Inbound>,
        patience: Duration,
    ) -> Result<Arc<Self>> {
        let stream = connect(socket, patience).await?;
        let (reader, writer) = stream.into_split();
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let connection = Arc::new(Self {
            role,
            key,
            writer: tokio::sync::Mutex::new(writer),
            pending: Arc::default(),
            next_request: AtomicU64::new(1),
            next_message: AtomicU64::new(1),
            session: session_tag(),
        });
        connection
            .send(Frame::Hello {
                principal: Principal::Agent { role },
                public_key,
                subscribe: vec![Audience::All, Audience::Role { role }],
            })
            .await?;
        tokio::spawn(read_frames(
            role,
            reader,
            Arc::clone(&connection.pending),
            inbound,
        ));
        Ok(connection)
    }

    /// Send `request` and wait up to `wait` for the response with the same id.
    ///
    /// # Errors
    /// Fails if the frame cannot be written, the connection closes, or the daemon does not
    /// answer in time.
    pub(crate) async fn request(
        &self,
        request: CoreRequest,
        wait: Duration,
    ) -> Result<CoreResponse> {
        let id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (answer, response) = oneshot::channel();
        lock(&self.pending).insert(id, answer);
        if let Err(error) = self.send(Frame::Request { id, request }).await {
            lock(&self.pending).remove(&id);
            return Err(error);
        }
        match tokio::time::timeout(wait, response).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => bail!(
                "cleanroomd closed the {} connection before answering request {id}",
                roles::name(self.role)
            ),
            Err(_) => {
                lock(&self.pending).remove(&id);
                bail!(
                    "cleanroomd did not answer request {id} within {} s",
                    wait.as_secs()
                )
            }
        }
    }

    /// Sign `body` with this role's key under the bus domain and publish it to everyone.
    ///
    /// # Errors
    /// Fails if the message cannot be signed or written.
    pub(crate) async fn publish(&self, body: BusBody) -> Result<()> {
        let number = self.next_message.fetch_add(1, Ordering::Relaxed);
        let message = BusMessage {
            id: format!("{}-{}-{number}", roles::name(self.role), self.session),
            at: now(),
            from: Principal::Agent { role: self.role },
            to: Audience::All,
            body,
        };
        let signed = sign(&self.key, domain::BUS, message).context("cannot sign a bus message")?;
        self.send(Frame::Publish(signed)).await
    }

    /// Write one envelope line.
    ///
    /// # Errors
    /// Fails if the frame cannot be encoded or written.
    async fn send(&self, frame: Frame) -> Result<()> {
        let mut line = serde_json::to_string(&Envelope {
            v: WIRE_VERSION,
            frame,
        })
        .context("cannot encode a frame")?;
        line.push('\n');
        let mut writer = self.writer.lock().await;
        writer
            .write_all(line.as_bytes())
            .await
            .context("cannot write to cleanroomd")?;
        writer.flush().await.context("cannot write to cleanroomd")
    }
}

/// The current time as an RFC 3339 UTC timestamp with seconds precision.
pub(crate) fn now() -> Timestamp {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

/// Connect to the socket, retrying while it does not exist yet or refuses connections.
///
/// # Errors
/// Fails on any other error, or when `patience` runs out.
async fn connect(socket: &Path, patience: Duration) -> Result<UnixStream> {
    let deadline = Instant::now() + patience;
    let mut announced = false;
    loop {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                if !announced {
                    tracing::info!(socket = %socket.display(), "waiting for cleanroomd");
                    announced = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot connect to cleanroomd at {}", socket.display())
                });
            }
        }
    }
}

/// Read frames until the connection ends: complete requests, forward events.
async fn read_frames(
    role: Role,
    reader: OwnedReadHalf,
    pending: Arc<Pending>,
    inbound: mpsc::Sender<Inbound>,
) {
    let mut lines = BufReader::new(reader).lines();
    let reason = loop {
        match lines.next_line().await {
            Ok(Some(line)) if line.trim().is_empty() => {}
            Ok(Some(line)) => match serde_json::from_str::<Envelope>(&line) {
                Ok(envelope) => deliver(role, envelope.frame, &pending, &inbound).await,
                Err(error) => tracing::warn!(
                    role = roles::name(role),
                    "ignoring an unreadable frame from cleanroomd: {error}"
                ),
            },
            Ok(None) => break "cleanroomd closed the connection".to_owned(),
            Err(error) => break format!("cannot read from cleanroomd: {error}"),
        }
    };
    lock(&pending).clear();
    if inbound
        .send(Inbound::Closed { role, reason })
        .await
        .is_err()
    {
        tracing::debug!("runner stopped before the connection closed");
    }
}

/// Route one frame from the daemon.
async fn deliver(role: Role, frame: Frame, pending: &Pending, inbound: &mpsc::Sender<Inbound>) {
    match frame {
        Frame::Response { id, response } => {
            let waiter = lock(pending).remove(&id);
            if let Some(waiter) = waiter {
                if waiter.send(response).is_err() {
                    tracing::debug!(id, "response arrived after its request gave up");
                }
            } else {
                tracing::warn!(id, "response for an unknown request id");
            }
        }
        Frame::Event(event) => {
            if inbound.send(Inbound::Event(Box::new(event))).await.is_err() {
                tracing::debug!("runner stopped; dropping an event");
            }
        }
        Frame::Hello { .. } | Frame::Publish(_) | Frame::Request { .. } => tracing::warn!(
            role = roles::name(role),
            "ignoring a client-side frame sent by cleanroomd"
        ),
    }
}

/// Lock the pending map; a panic elsewhere cannot leave it inconsistent, so poisoning is ignored.
fn lock(pending: &Pending) -> MutexGuard<'_, HashMap<u64, oneshot::Sender<CoreResponse>>> {
    pending.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Process start time and pid, in hex.
fn session_tag() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("{millis:x}{:x}", std::process::id())
}
