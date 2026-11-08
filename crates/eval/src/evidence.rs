//! Ground truth the harness takes outside every sandbox: hashes of the evidence the agents see,
//! the run's receipt log, and the agents' log.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cleanroom_proto::{Action, Outcome, Principal, Receipt, Signed};
use sha2::{Digest as _, Sha256};

use crate::record::ReceiptCounts;

/// The victim's directories under the daemon's state and where agents see them.
const MOUNTS: [(&str, &str); 3] = [
    ("run/acme-fs/share", "/evidence/acme-fs"),
    ("run/acme-fs/drop", "/evidence/dropbox"),
    ("run/acme-fs/logs", "/evidence/logs"),
];

/// SHA-256 of every evidence file, by the path agents see.
pub(crate) type Fingerprint = BTreeMap<String, String>;

/// Hash every file the agents see under `/evidence`.
///
/// # Errors
/// Fails if a directory cannot be listed or a file cannot be read.
pub(crate) fn fingerprint(state: &Path) -> Result<Fingerprint> {
    let mut hashes = BTreeMap::new();
    for (host, guest) in MOUNTS {
        let root = state.join(host);
        for path in files_under(&root)? {
            let relative = path
                .strip_prefix(&root)
                .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            hashes.insert(
                format!("{guest}/{}", relative.display()),
                hex::encode(Sha256::digest(&bytes)),
            );
        }
    }
    Ok(hashes)
}

/// Files added (`+`), removed (`-`) or changed (`~`) between two fingerprints.
pub(crate) fn changes(before: &Fingerprint, after: &Fingerprint) -> Vec<String> {
    let removed_or_changed = before
        .iter()
        .filter_map(|(path, hash)| match after.get(path) {
            None => Some(format!("-{path}")),
            Some(now) if now != hash => Some(format!("~{path}")),
            Some(_) => None,
        });
    let added = after
        .keys()
        .filter(|path| !before.contains_key(*path))
        .map(|path| format!("+{path}"));
    removed_or_changed.chain(added).collect()
}

/// Regular files under `root`, recursively; a missing root has none. Symlinks are not followed.
///
/// # Errors
/// Fails if a directory cannot be listed.
fn files_under(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot list {}", dir.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
            let kind = entry
                .file_type()
                .with_context(|| format!("cannot inspect {}", entry.path().display()))?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if !kind.is_symlink() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

/// Count the agents' command receipts in `receipts.ndjson`.
///
/// # Errors
/// Fails if the log cannot be read or a line is not a signed receipt.
pub(crate) fn receipts(log: &Path) -> Result<ReceiptCounts> {
    let text = fs::read_to_string(log).with_context(|| format!("cannot read {}", log.display()))?;
    let mut counts = ReceiptCounts::default();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let signed: Signed<Receipt> = serde_json::from_str(line)
            .with_context(|| format!("{} holds a line that is not a receipt", log.display()))?;
        counts.total += 1;
        let receipt = signed.body;
        if matches!(receipt.actor, Principal::Agent { .. })
            && matches!(receipt.action, Action::Exec { .. })
        {
            match receipt.outcome {
                Outcome::Allowed => counts.agent_exec_allowed += 1,
                Outcome::Denied { .. } => counts.agent_exec_denied += 1,
            }
        }
    }
    Ok(counts)
}

/// Model call retries in the agents' log, and how many were HTTP 429.
///
/// # Errors
/// Fails if the log exists but cannot be read.
pub(crate) fn retries(log: &Path) -> Result<(u32, u32)> {
    let text = match fs::read(log) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", log.display()));
        }
    };
    let mut counts = (0, 0);
    for line in text
        .lines()
        .filter(|line| line.contains("model call failed"))
    {
        counts.0 += 1;
        if line.contains("429") || line.contains("Too Many Requests") {
            counts.1 += 1;
        }
    }
    Ok(counts)
}

#[cfg(test)]
#[allow(
    clippy::missing_panics_doc,
    reason = "tests panic on failure by design. `allow`, not `expect`: the lint only runs under \
              the strict Clippy profile"
)]
mod tests {
    use std::collections::BTreeMap;

    use super::changes;

    #[test]
    fn changes_name_added_removed_and_changed_files() {
        let before = BTreeMap::from([
            ("/evidence/logs/syslog".to_owned(), "a".to_owned()),
            ("/evidence/logs/auth.log".to_owned(), "b".to_owned()),
            ("/evidence/dropbox/payroll.csv".to_owned(), "c".to_owned()),
        ]);
        let after = BTreeMap::from([
            ("/evidence/logs/syslog".to_owned(), "a".to_owned()),
            ("/evidence/logs/auth.log".to_owned(), "x".to_owned()),
            ("/evidence/acme-fs/new.txt".to_owned(), "d".to_owned()),
        ]);
        assert_eq!(
            changes(&before, &after),
            [
                "-/evidence/dropbox/payroll.csv",
                "~/evidence/logs/auth.log",
                "+/evidence/acme-fs/new.txt"
            ]
        );
        assert!(changes(&after, &after).is_empty(), "no change");
    }
}
