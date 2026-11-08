//! Enrolled people: `keys/members.ndjson`, one admin-signed `Signed<Member>` per line.
//!
//! With nobody enrolled the daemon runs in bootstrap mode: any human key on the socket (mode
//! 0600, so only this user) may approve, and the first enrollment must be an admin enrolling
//! their own key. Once someone is enrolled, only an enrolled admin enrolls and only enrolled
//! commanders and admins approve.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{key_id, verifying_key_from_hex};
use cleanroom_proto::{Member, MemberRole, Signed};

/// The enrolled members.
#[derive(Debug)]
pub(crate) struct Members {
    /// The members file.
    path: PathBuf,
    /// Current members; a later enrollment of the same key replaces the earlier one.
    list: Vec<Member>,
}

impl Members {
    /// Load the members file; a missing file means nobody is enrolled.
    ///
    /// # Errors
    /// Fails if the file cannot be read or a line is not a signed member record.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let mut list: Vec<Member> = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let signed: Signed<Member> = serde_json::from_str(line)
                .with_context(|| format!("{} holds a malformed member", path.display()))?;
            list.retain(|member| member.key_id != signed.body.key_id);
            list.push(signed.body);
        }
        Ok(Self {
            path: path.to_owned(),
            list,
        })
    }

    /// True when `key` may sign approvals.
    pub(crate) fn may_approve(&self, key: &str) -> bool {
        self.list.is_empty()
            || self.list.iter().any(|member| {
                member.key_id == key
                    && matches!(member.role, MemberRole::Admin | MemberRole::Commander)
            })
    }

    /// Enroll the member in `signed`, already verified as signed by `enroller`.
    ///
    /// # Errors
    /// Fails if the record's key id doesn't match its public key, the enroller may not enroll,
    /// or the file cannot be written.
    pub(crate) fn enroll(&mut self, enroller: &str, signed: Signed<Member>) -> Result<()> {
        let member = &signed.body;
        let key = verifying_key_from_hex(&member.public_key)
            .context("the member's public key is malformed")?;
        if key_id(&key) != member.key_id {
            bail!("the member's key_id does not match its public key");
        }
        if self.list.is_empty() {
            if member.key_id != enroller || member.role != MemberRole::Admin {
                bail!(
                    "nobody is enrolled yet: the first enrollment must be an admin enrolling their own key"
                );
            }
        } else if !self
            .list
            .iter()
            .any(|enrolled| enrolled.key_id == enroller && enrolled.role == MemberRole::Admin)
        {
            bail!("only an enrolled admin can enroll members");
        }
        let mut line = serde_json::to_vec(&signed).context("cannot encode the member")?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line))
            .with_context(|| format!("cannot write {}", self.path.display()))?;
        self.list
            .retain(|enrolled| enrolled.key_id != member.key_id);
        self.list.push(signed.body);
        Ok(())
    }
}
