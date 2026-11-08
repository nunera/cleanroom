//! The receipt log: `receipts.ndjson`, one `Signed<Receipt>` per line.
//!
//! Each receipt is signed by the daemon key under `cleanroom/v1/receipt`, its `seq` is its
//! 1-based line number, and its `prev` is the digest of the previous signed receipt (`sha256:`
//! and 64 zeros for the first). Editing, deleting or reordering a line breaks the chain at that
//! entry; [`verify`] walks it offline and names the first break.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cleanroom_proto::sign::{self, digest_of};
use cleanroom_proto::{Action, Digest, Outcome, Principal, Receipt, Signed, domain};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::now;

/// `prev` of the first receipt.
const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The open log: where the next receipt goes and what it chains to.
#[derive(Debug)]
pub(crate) struct Log {
    /// The file, for verification.
    path: PathBuf,
    /// Append-only handle.
    file: File,
    /// `seq` of the next receipt.
    next_seq: u64,
    /// Digest of the last signed receipt.
    prev: Digest,
}

/// What a walk of the chain found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Report {
    /// Receipts in the log.
    pub(crate) entries: u64,
    /// `seq` (line number) of the first receipt that does not verify or does not chain.
    pub(crate) first_break: Option<u64>,
}

impl Log {
    /// Open the log at `path` (mode 0600), continuing the chain after its last entry.
    ///
    /// # Errors
    /// Fails if the file cannot be read or opened for appending.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let mut entries = 0_u64;
        let mut prev = GENESIS.to_owned();
        for line in lines(&text) {
            entries += 1;
            if let Ok(signed) = serde_json::from_str::<Signed<Receipt>>(line)
                && let Ok(digest) = digest_of(&signed)
            {
                prev = digest;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        if !text.is_empty() && !text.ends_with('\n') {
            // A torn last write: start the next receipt on its own line.
            file.write_all(b"\n")
                .with_context(|| format!("cannot write {}", path.display()))?;
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            next_seq: entries + 1,
            prev,
        })
    }

    /// Sign `actor`'s `action` and its `outcome`, append it, and return its `seq`.
    ///
    /// # Errors
    /// Fails if the receipt cannot be signed or written to disk.
    pub(crate) fn append(
        &mut self,
        key: &SigningKey,
        actor: Principal,
        action: Action,
        outcome: Outcome,
    ) -> Result<u64> {
        let seq = self.next_seq;
        let receipt = Receipt {
            seq,
            prev: self.prev.clone(),
            at: now(),
            actor,
            action,
            outcome,
        };
        let signed = sign::sign(key, domain::RECEIPT, receipt).context("cannot sign a receipt")?;
        let digest = digest_of(&signed).context("cannot digest a receipt")?;
        let mut line = serde_json::to_vec(&signed).context("cannot encode a receipt")?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .and_then(|()| self.file.sync_data())
            .with_context(|| format!("cannot append to {}", self.path.display()))?;
        self.prev = digest;
        self.next_seq += 1;
        Ok(seq)
    }

    /// Walk the whole log on disk.
    ///
    /// # Errors
    /// Fails if the file cannot be read.
    pub(crate) fn verify(&self, key: &VerifyingKey) -> Result<Report> {
        let text = fs::read_to_string(&self.path)
            .with_context(|| format!("cannot read {}", self.path.display()))?;
        Ok(verify(&text, key))
    }
}

/// Walk the chain in `text`: every line must parse, carry the daemon's signature, sit at the
/// position its `seq` names, and point at its predecessor's digest.
pub(crate) fn verify(text: &str, key: &VerifyingKey) -> Report {
    let mut prev = GENESIS.to_owned();
    let mut entries = 0_u64;
    let mut first_break = None;
    for line in lines(text) {
        entries += 1;
        if first_break.is_none() {
            match link(line, entries, &prev, key) {
                Some(digest) => prev = digest,
                None => first_break = Some(entries),
            }
        }
    }
    Report {
        entries,
        first_break,
    }
}

/// The digest of the receipt on `line` if it verifies and chains to `prev` at position `seq`.
fn link(line: &str, seq: u64, prev: &str, key: &VerifyingKey) -> Option<Digest> {
    let signed: Signed<Receipt> = serde_json::from_str(line).ok()?;
    sign::verify(&signed, key, domain::RECEIPT).ok()?;
    if signed.body.seq != seq || signed.body.prev != prev {
        return None;
    }
    digest_of(&signed).ok()
}

/// Non-blank lines.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|line| !line.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use cleanroom_proto::Role;
    use cleanroom_proto::sign::signing_key_from_hex;

    use super::*;

    /// A fresh log file under the system temp directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            Self(std::env::temp_dir().join(format!(
                "cleanroomd-{name}-{}-{nanos}.ndjson",
                std::process::id()
            )))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_file(&self.0) {
                assert_eq!(error.kind(), ErrorKind::NotFound, "cannot clean up {error}");
            }
        }
    }

    fn key() -> SigningKey {
        signing_key_from_hex(&"42".repeat(32)).expect("fixed 32-byte test seed")
    }

    fn exec(argv: &str) -> Action {
        Action::Exec {
            stratum: "hunter".into(),
            argv: argv.split(' ').map(str::to_owned).collect(),
        }
    }

    /// Append three receipts and return the file's lines.
    fn three(log_path: &Path) -> Vec<String> {
        let mut log = Log::open(log_path).expect("temp log opens");
        let hunter = Principal::Agent { role: Role::Hunter };
        let denied = Outcome::Denied {
            reason: "evidence is mounted read_only for hunter".into(),
        };
        for (argv, outcome) in [
            ("ls -la /evidence", Outcome::Allowed),
            ("sh -c rm -rf /evidence/*", denied),
            ("sha256sum /evidence/logs/auth.log", Outcome::Allowed),
        ] {
            log.append(&key(), hunter.clone(), exec(argv), outcome)
                .expect("receipt appends");
        }
        fs::read_to_string(log_path)
            .expect("log is readable")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let scratch = Scratch::new("intact");
        let lines = three(&scratch.0);
        let report = verify(&lines.join("\n"), &key().verifying_key());
        assert_eq!(
            report,
            Report {
                entries: 3,
                first_break: None
            },
            "three intact receipts"
        );
    }

    #[test]
    fn an_edited_receipt_breaks_the_chain_at_that_entry() {
        let scratch = Scratch::new("edited");
        let mut lines = three(&scratch.0);
        let second = lines.get_mut(1).expect("three receipts were written");
        assert!(second.contains("denied"), "line 2 is the denial: {second}");
        *second = second.replace(
            r#"{"kind":"denied","reason":"evidence is mounted read_only for hunter"}"#,
            r#"{"kind":"allowed"}"#,
        );
        let report = verify(&lines.join("\n"), &key().verifying_key());
        assert_eq!(
            report.first_break,
            Some(2),
            "the rewritten outcome no longer matches its signature"
        );
        assert_eq!(report.entries, 3, "every line still counts as an entry");
    }

    #[test]
    fn a_removed_receipt_breaks_the_chain_where_it_was() {
        let scratch = Scratch::new("removed");
        let mut lines = three(&scratch.0);
        lines.remove(1);
        let report = verify(&lines.join("\n"), &key().verifying_key());
        assert_eq!(
            report.first_break,
            Some(2),
            "receipt 3 now sits at line 2 and its prev names the missing receipt"
        );
    }

    #[test]
    fn a_reopened_log_keeps_chaining() {
        let scratch = Scratch::new("reopened");
        three(&scratch.0);
        let mut log = Log::open(&scratch.0).expect("log reopens");
        let seq = log
            .append(
                &key(),
                Principal::System,
                Action::Detonate {
                    scenario: "ransomware".into(),
                },
                Outcome::Allowed,
            )
            .expect("receipt appends");
        assert_eq!(seq, 4, "numbering continues after the existing entries");
        let report = log.verify(&key().verifying_key()).expect("log is readable");
        assert_eq!(
            report,
            Report {
                entries: 4,
                first_break: None
            },
            "the chain continues across a reopen"
        );
    }
}
