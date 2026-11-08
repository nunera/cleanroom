//! Record/replay store for model calls, keyed by the SHA-256 of the exact request body.
//!
//! Record mode stores every live response with its latency. Replay mode never touches the
//! network: it answers from the store, first by exact request key, then, when this run's
//! conversation drifted from the recording (file times, hashes or record timestamps differ), by
//! the call's position in its stream, for example the third `hunter.agent` call. Replies say
//! which, so status lines can label them, and arrive after the recorded latency so a replayed
//! demo runs at the pace of the live one.
//!
//! Layout under the cache directory: `<key>.request.json`, `<key>.response.json`,
//! `<key>.latency` (milliseconds), and `sequence/<stream>.<position>` holding the key of that
//! call in the latest recording.

use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

/// Cache key of a request: lowercase hex SHA-256 of its body bytes.
pub(crate) fn key(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// How a replayed response was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hit {
    /// The request matched a recorded request byte for byte.
    Exact,
    /// The request differed; the response recorded at the same stream position was used.
    Sequence,
}

/// A sequence of calls that replays in order: one role's agent steps or its safety checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Stream {
    /// Role name, for example `hunter`.
    pub(crate) role: &'static str,
    /// `agent` or `safety`.
    pub(crate) purpose: &'static str,
}

/// One call's place in its stream, for example `hunter.agent.3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    /// The stream.
    stream: Stream,
    /// 1-based position within the stream.
    position: u32,
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            self.stream.role, self.stream.purpose, self.position
        )
    }
}

/// A recorded response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Replayed {
    /// The response body as the server sent it.
    pub(crate) body: Vec<u8>,
    /// How it was found.
    pub(crate) hit: Hit,
    /// How long the live call took.
    pub(crate) latency: Duration,
}

/// The on-disk store plus per-stream call positions for this investigation.
#[derive(Debug)]
pub(crate) struct Store {
    /// Cache directory.
    dir: PathBuf,
    /// Calls made so far per stream.
    positions: Mutex<HashMap<Stream, u32>>,
}

impl Store {
    /// A store rooted at `dir` (created on first record).
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            positions: Mutex::new(HashMap::new()),
        }
    }

    /// Where the store lives.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The slot of the next call in `stream`.
    pub(crate) fn next_slot(&self, stream: Stream) -> Slot {
        let position = *self
            .positions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(stream)
            .and_modify(|position| *position += 1)
            .or_insert(1);
        Slot { stream, position }
    }

    /// Start every stream at position 1 again: a new investigation began.
    pub(crate) fn restart(&self) {
        self.positions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Store a live exchange and how long it took.
    ///
    /// # Errors
    /// Fails if the cache directory or a file cannot be written.
    pub(crate) async fn record(
        &self,
        slot: Slot,
        key: &str,
        exchange: (&[u8], &[u8]),
        latency: Duration,
    ) -> Result<()> {
        let (request, response) = exchange;
        let sequence = self.dir.join("sequence");
        tokio::fs::create_dir_all(&sequence)
            .await
            .with_context(|| format!("cannot create {}", sequence.display()))?;
        // Two roles can send byte-identical requests (the same listing to the safety model), so
        // temporary names carry the slot, which is unique within this process.
        let writer = slot.to_string();
        let millis = latency.as_millis().to_string();
        for (suffix, bytes) in [
            ("request.json", request),
            ("response.json", response),
            ("latency", millis.as_bytes()),
        ] {
            let path = self.dir.join(format!("{key}.{suffix}"));
            write_atomic(&path, bytes, &writer).await?;
        }
        write_atomic(&sequence.join(&writer), key.as_bytes(), &writer).await
    }

    /// Find the recorded response for a request.
    ///
    /// # Errors
    /// Fails if neither the exact key nor the slot was recorded, or a file is unreadable.
    pub(crate) async fn replay(&self, slot: Slot, key: &str) -> Result<Replayed> {
        if let Some(body) = read_if_present(&self.dir.join(format!("{key}.response.json"))).await? {
            return Ok(Replayed {
                body,
                hit: Hit::Exact,
                latency: self.latency(key).await,
            });
        }
        let pointer = self.dir.join("sequence").join(slot.to_string());
        let Some(recorded) = read_if_present(&pointer).await? else {
            bail!(
                "replay store {} has no response for {slot}",
                self.dir.display()
            );
        };
        let recorded = String::from_utf8_lossy(&recorded);
        let recorded = recorded.trim();
        if recorded.len() != 64 || !recorded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("{} does not hold a request key", pointer.display());
        }
        let path = self.dir.join(format!("{recorded}.response.json"));
        let body = tokio::fs::read(&path)
            .await
            .with_context(|| format!("cannot read {}", path.display()))?;
        Ok(Replayed {
            body,
            hit: Hit::Sequence,
            latency: self.latency(recorded).await,
        })
    }

    /// The recorded latency of `key`; zero when it was not recorded.
    async fn latency(&self, key: &str) -> Duration {
        let path = self.dir.join(format!("{key}.latency"));
        tokio::fs::read_to_string(&path)
            .await
            .ok()
            .and_then(|millis| millis.trim().parse::<u64>().ok())
            .map_or(Duration::ZERO, Duration::from_millis)
    }
}

/// Read a file, or `None` when it does not exist.
///
/// # Errors
/// Fails on any error other than a missing file.
async fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Write `bytes` to `path` through a temporary file named after `writer`, so a crash never
/// leaves half a response and concurrent writers of the same file don't collide.
///
/// # Errors
/// Fails if the temporary file cannot be written or renamed.
async fn write_atomic(path: &Path, bytes: &[u8], writer: &str) -> Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".");
    temporary.push(writer);
    temporary.push(".tmp");
    tokio::fs::write(&temporary, bytes)
        .await
        .with_context(|| format!("cannot write {}", path.display()))?;
    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::Role;

    use super::*;
    use crate::llm::{Message, request_body};
    use crate::roles;

    fn conversation(tool_output: &str) -> Vec<u8> {
        let messages = [
            Message::System {
                content: roles::system_prompt(Role::Hunter, true),
            },
            Message::User {
                content: "Incident INC-7: ransomware on acme-fs".to_owned(),
            },
            Message::Tool {
                tool_call_id: "call_0".to_owned(),
                content: tool_output.to_owned(),
            },
        ];
        request_body(
            "nvidia/nemotron-3.5-lightning-30b-a3b",
            &messages,
            &roles::tool_specs(Role::Hunter, true),
            2048,
        )
        .expect("request serializes")
    }

    #[test]
    fn same_conversation_gives_the_same_key() {
        assert_eq!(
            key(&conversation("exit code 0\nREADME_RESTORE_FILES.txt")),
            key(&conversation("exit code 0\nREADME_RESTORE_FILES.txt")),
            "request bodies carry no volatile fields, so replay can match them"
        );
        assert_ne!(
            key(&conversation("exit code 0\nREADME_RESTORE_FILES.txt")),
            key(&conversation("exit code 0\nREADME_RESTORE_FILES.txt\n")),
            "any change in what the model sees is a different request"
        );
    }

    #[tokio::test]
    async fn replay_prefers_exact_then_falls_back_by_position() {
        let dir = std::env::temp_dir().join(format!(
            "cleanroom-agents-cache-test-{}",
            std::process::id()
        ));
        let store = Store::new(dir.clone());
        let hunter = Stream {
            role: "hunter",
            purpose: "agent",
        };
        let recorded = conversation("recorded listing");
        let recorded_key = key(&recorded);
        let first = store.next_slot(hunter);
        let response = b"{\"choices\":[]}";
        store
            .record(
                first,
                &recorded_key,
                (&recorded, response),
                Duration::from_millis(1_250),
            )
            .await
            .expect("temp dir is writable");

        let exact = store
            .replay(first, &recorded_key)
            .await
            .expect("recorded request replays");
        assert_eq!(
            exact,
            Replayed {
                body: response.to_vec(),
                hit: Hit::Exact,
                latency: Duration::from_millis(1_250),
            },
            "exact key wins and keeps the recorded pace"
        );

        let drifted = key(&conversation("listing with new file times"));
        let fallback = store
            .replay(first, &drifted)
            .await
            .expect("same position replays");
        assert_eq!(
            fallback.hit,
            Hit::Sequence,
            "a drifted request falls back to its position"
        );

        let second = store.next_slot(hunter);
        assert!(
            store.replay(second, &drifted).await.is_err(),
            "a call that was never recorded is a replay miss"
        );
        store.restart();
        assert_eq!(
            store.next_slot(hunter),
            first,
            "a new investigation restarts positions"
        );
        std::fs::remove_dir_all(&dir).expect("temp dir is removable");
    }
}
