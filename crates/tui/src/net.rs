//! The live link to cleanroomd: one Unix socket carrying NDJSON envelopes in both directions.

use std::io;
use std::path::Path;

use cleanroom_proto::Envelope;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::app::Inbound;

/// `--record`: appends every line received from cleanroomd to a file, verbatim, so the file is a
/// valid `--replay` input.
#[derive(Debug)]
pub(crate) struct Recorder {
    /// The recording, flushed after every line.
    file: BufWriter<File>,
}

impl Recorder {
    /// Create (or truncate) the recording at `path`.
    ///
    /// # Errors
    /// Fails when the file can't be created.
    pub(crate) async fn create(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: BufWriter::new(File::create(path).await?),
        })
    }

    /// Append one frame line and flush, so a crash loses nothing that was already shown.
    ///
    /// # Errors
    /// Fails when the write or flush fails.
    async fn append(&mut self, line: &str) -> io::Result<()> {
        self.file.write_all(line.as_bytes()).await?;
        self.file.write_all(b"\n").await?;
        self.file.flush().await
    }
}

/// Connect to `socket`, send `hello`, and start the reader and writer tasks.
///
/// The reader forwards every received line to `inbound` (and to `recorder`); the writer sends
/// whatever is queued on the returned sender, in order.
///
/// # Errors
/// Fails when the socket can't be reached or `hello` can't be written.
pub(crate) async fn connect(
    socket: &Path,
    hello: &Envelope,
    recorder: Option<Recorder>,
    inbound: UnboundedSender<Inbound>,
) -> io::Result<UnboundedSender<Envelope>> {
    let stream = UnixStream::connect(socket).await?;
    let (read, mut write) = stream.into_split();
    write_frame(&mut write, hello).await?;
    let (outbound, queue) = mpsc::unbounded_channel();
    tokio::spawn(write_loop(write, queue, inbound.clone()));
    tokio::spawn(read_loop(read, recorder, inbound));
    Ok(outbound)
}

/// Write one envelope as a JSON line.
///
/// # Errors
/// Fails when the envelope can't be serialized or the socket write fails.
async fn write_frame(write: &mut OwnedWriteHalf, envelope: &Envelope) -> io::Result<()> {
    let mut line = serde_json::to_vec(envelope).map_err(io::Error::other)?;
    line.push(b'\n');
    write.write_all(&line).await
}

/// Send queued envelopes until the queue closes or a write fails.
///
/// # Errors
/// Fails only when the console has already gone away, so there is nobody left to tell.
async fn write_loop(
    mut write: OwnedWriteHalf,
    mut queue: UnboundedReceiver<Envelope>,
    inbound: UnboundedSender<Inbound>,
) -> Result<(), SendError<Inbound>> {
    while let Some(envelope) = queue.recv().await {
        if let Err(error) = write_frame(&mut write, &envelope).await {
            return inbound.send(Inbound::Closed(format!(
                "sending to cleanroomd failed: {error}"
            )));
        }
    }
    Ok(())
}

/// Forward received lines until the connection ends.
///
/// # Errors
/// Fails only when the console has already gone away, so there is nobody left to tell.
async fn read_loop(
    read: OwnedReadHalf,
    mut recorder: Option<Recorder>,
    inbound: UnboundedSender<Inbound>,
) -> Result<(), SendError<Inbound>> {
    let mut lines = BufReader::new(read).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                return inbound.send(Inbound::Closed(
                    "cleanroomd closed the connection".to_owned(),
                ));
            }
            Err(error) => {
                return inbound.send(Inbound::Closed(format!(
                    "reading from cleanroomd failed: {error}"
                )));
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(active) = recorder.as_mut()
            && let Err(error) = active.append(&line).await
        {
            recorder = None;
            inbound.send(Inbound::RecordFailed(error.to_string()))?;
        }
        inbound.send(Inbound::parse(&line))?;
    }
}
