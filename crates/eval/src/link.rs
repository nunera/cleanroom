//! The harness's human connection to `cleanroomd`.
//!
//! It says `hello` with a fresh Ed25519 key, sends requests and matches their responses by id,
//! signs the commander's decisions, and hands over every bus event with its arrival time.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{generate_key, key_id, sign};
use cleanroom_proto::{
    ApprovalDecision, Audience, BusMessage, CoreRequest, CoreResponse, Envelope, Frame, Principal,
    Signed, WIRE_VERSION, domain,
};
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// How long a quick request (approve, verify) may take.
const QUICK: Duration = Duration::from_secs(30);

/// A bus event and when it arrived.
#[derive(Debug)]
pub(crate) struct Arrival {
    /// Arrival time.
    pub(crate) at: Instant,
    /// The event as the daemon sent it.
    pub(crate) event: Signed<BusMessage>,
}

/// What the reader task hands over.
#[derive(Debug)]
enum Inbound {
    /// A bus event.
    Event(Box<Arrival>),
    /// The answer to a request.
    Response {
        /// The request's id.
        id: u64,
        /// The answer.
        response: CoreResponse,
    },
    /// The connection ended.
    Closed(String),
}

/// One human connection.
#[derive(Debug)]
pub(crate) struct Link {
    /// Signs the hello key's decisions.
    key: SigningKey,
    /// Write half.
    writer: OwnedWriteHalf,
    /// Everything the reader task received.
    inbound: mpsc::UnboundedReceiver<Inbound>,
    /// Events that arrived while a request waited for its response.
    queued: VecDeque<Arrival>,
    /// Next request id.
    next_id: u64,
}

impl Link {
    /// Connect (waiting up to `patience` for the socket) and say hello as a human.
    ///
    /// # Errors
    /// Fails if the socket does not come up in time or the hello cannot be written.
    pub(crate) async fn open(socket: &Path, patience: Duration) -> Result<Self> {
        let stream = connect(socket, patience).await?;
        let (reader, writer) = stream.into_split();
        let (sender, inbound) = mpsc::unbounded_channel();
        tokio::spawn(read(reader, sender));
        let key = generate_key().context("cannot generate a session key")?;
        let public = key.verifying_key();
        let mut link = Self {
            key,
            writer,
            inbound,
            queued: VecDeque::new(),
            next_id: 1,
        };
        link.send(Frame::Hello {
            principal: Principal::Human {
                key_id: key_id(&public),
            },
            public_key: hex::encode(public.as_bytes()),
            subscribe: vec![Audience::All, Audience::Humans],
        })
        .await?;
        Ok(link)
    }

    /// Send `request` and wait up to `wait` for its response; events that arrive meanwhile
    /// are kept for [`Link::next_event`].
    ///
    /// # Errors
    /// Fails if the request cannot be written, the connection closes, or no answer comes in
    /// time.
    pub(crate) async fn request(
        &mut self,
        request: CoreRequest,
        wait: Duration,
    ) -> Result<CoreResponse> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(Frame::Request { id, request }).await?;
        let deadline = Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, self.inbound.recv()).await {
                Ok(Some(Inbound::Response {
                    id: answered,
                    response,
                })) if answered == id => return Ok(response),
                Ok(Some(Inbound::Response { id: stale, .. })) => {
                    tracing::debug!(id = stale, "late response");
                }
                Ok(Some(Inbound::Event(arrival))) => self.queued.push_back(*arrival),
                Ok(Some(Inbound::Closed(reason))) => bail!("cleanroomd: {reason}"),
                Ok(None) => bail!("the cleanroomd reader stopped"),
                Err(_) => bail!("cleanroomd did not answer within {} s", wait.as_secs()),
            }
        }
    }

    /// The next bus event, or `None` once `deadline` passes.
    ///
    /// # Errors
    /// Fails if the connection closes.
    pub(crate) async fn next_event(&mut self, deadline: Instant) -> Result<Option<Arrival>> {
        if let Some(arrival) = self.queued.pop_front() {
            return Ok(Some(arrival));
        }
        loop {
            match tokio::time::timeout_at(deadline, self.inbound.recv()).await {
                Ok(Some(Inbound::Event(arrival))) => return Ok(Some(*arrival)),
                Ok(Some(Inbound::Response { id, .. })) => {
                    tracing::debug!(id, "late response");
                }
                Ok(Some(Inbound::Closed(reason))) => bail!("cleanroomd: {reason}"),
                Ok(None) => bail!("the cleanroomd reader stopped"),
                Err(_) => return Ok(None),
            }
        }
    }

    /// Reject a pending tool request or a containment proposal as the commander.
    ///
    /// # Errors
    /// Fails if the decision cannot be signed or sent, or the daemon does not answer.
    pub(crate) async fn reject(&mut self, subject_id: &str) -> Result<CoreResponse> {
        let decision = ApprovalDecision {
            subject_id: subject_id.to_owned(),
            approved: false,
            at: humantime::format_rfc3339_seconds(SystemTime::now()).to_string(),
        };
        let signed =
            sign(&self.key, domain::APPROVAL, decision).context("cannot sign the decision")?;
        self.request(CoreRequest::Approve(signed), QUICK).await
    }

    /// `verify_log`: receipts and the first break, if any.
    ///
    /// # Errors
    /// Fails if the daemon does not answer with a verification.
    pub(crate) async fn verify_log(&mut self) -> Result<(u64, Option<u64>)> {
        match self.request(CoreRequest::VerifyLog, QUICK).await? {
            CoreResponse::LogVerified {
                entries,
                first_break,
            } => Ok((entries, first_break)),
            CoreResponse::Error { message } => bail!("verify_log: {message}"),
            CoreResponse::Exec(_)
            | CoreResponse::Tool { .. }
            | CoreResponse::Admitted { .. }
            | CoreResponse::AdmitRejected { .. }
            | CoreResponse::Ok => bail!("cleanroomd answered verify_log with something else"),
        }
    }

    /// Write one envelope line.
    ///
    /// # Errors
    /// Fails if the frame cannot be encoded or written.
    async fn send(&mut self, frame: Frame) -> Result<()> {
        let mut line = serde_json::to_string(&Envelope {
            v: WIRE_VERSION,
            frame,
        })
        .context("cannot encode a frame")?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .context("cannot write to cleanroomd")?;
        self.writer
            .flush()
            .await
            .context("cannot write to cleanroomd")
    }
}

/// Connect, retrying while the socket does not exist yet or refuses connections.
///
/// # Errors
/// Fails on any other error, or when `patience` runs out.
async fn connect(socket: &Path, patience: Duration) -> Result<UnixStream> {
    let deadline = Instant::now() + patience;
    loop {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot connect to cleanroomd at {}", socket.display())
                });
            }
        }
    }
}

/// Forward every frame until the connection ends.
async fn read(reader: OwnedReadHalf, sender: mpsc::UnboundedSender<Inbound>) {
    let mut lines = BufReader::new(reader).lines();
    let reason = loop {
        match lines.next_line().await {
            Ok(Some(line)) if line.trim().is_empty() => {}
            Ok(Some(line)) => {
                let inbound = match serde_json::from_str::<Envelope>(&line) {
                    Ok(Envelope {
                        frame: Frame::Event(event),
                        ..
                    }) => Inbound::Event(Box::new(Arrival {
                        at: Instant::now(),
                        event,
                    })),
                    Ok(Envelope {
                        frame: Frame::Response { id, response },
                        ..
                    }) => Inbound::Response { id, response },
                    Ok(Envelope {
                        frame: Frame::Hello { .. } | Frame::Publish(_) | Frame::Request { .. },
                        ..
                    }) => continue,
                    Err(error) => {
                        tracing::warn!("ignoring an unreadable frame from cleanroomd: {error}");
                        continue;
                    }
                };
                if sender.send(inbound).is_err() {
                    return;
                }
            }
            Ok(None) => break "cleanroomd closed the connection".to_owned(),
            Err(error) => break format!("cannot read from cleanroomd: {error}"),
        }
    };
    if sender.send(Inbound::Closed(reason)).is_err() {
        tracing::debug!("the harness stopped before the connection closed");
    }
}
