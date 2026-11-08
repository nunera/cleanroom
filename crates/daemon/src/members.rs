//! Enrolled people: `keys/members.ndjson`, one admin-signed line per enrollment
//! (`Signed<Member>`, domain `cleanroom/v1/enroll`) or revocation (`Signed<Revocation>`,
//! domain `cleanroom/v1/revoke`), applied in order.
//!
//! With nobody enrolled the daemon runs in bootstrap mode: any human key on the socket (mode
//! 0600, so only this user) may approve, and the first enrollment must be an admin enrolling
//! their own key. Once someone is enrolled, only an enrolled admin enrolls or revokes and only
//! enrolled commanders and admins approve. The last admin cannot be revoked, so the list never
//! empties back into bootstrap mode.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{key_id, verifying_key_from_hex};
use cleanroom_proto::{Member, MemberRole, Revocation, Signed, domain};
use serde::Serialize;

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
            let malformed = || format!("{} holds a malformed member line", path.display());
            let entry: serde_json::Value = serde_json::from_str(line).with_context(malformed)?;
            match entry.get("domain").and_then(serde_json::Value::as_str) {
                Some(domain::ENROLL) => {
                    let signed: Signed<Member> =
                        serde_json::from_value(entry).with_context(malformed)?;
                    list.retain(|member| member.key_id != signed.body.key_id);
                    list.push(signed.body);
                }
                Some(domain::REVOKE) => {
                    let signed: Signed<Revocation> =
                        serde_json::from_value(entry).with_context(malformed)?;
                    list.retain(|member| member.key_id != signed.body.key_id);
                }
                _ => bail!(malformed()),
            }
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
        } else if !self.is_admin(enroller) {
            bail!("only an enrolled admin can enroll members");
        }
        self.append(&signed)?;
        self.list
            .retain(|enrolled| enrolled.key_id != member.key_id);
        self.list.push(signed.body);
        Ok(())
    }

    /// Revoke the member in `signed`, already verified as signed by `revoker`.
    ///
    /// # Errors
    /// Fails if the revoker is not an enrolled admin, the key is not enrolled, it is the last
    /// admin, or the file cannot be written.
    pub(crate) fn revoke(&mut self, revoker: &str, signed: Signed<Revocation>) -> Result<()> {
        if !self.is_admin(revoker) {
            bail!("only an enrolled admin can revoke members");
        }
        let target = &signed.body.key_id;
        let Some(member) = self.list.iter().find(|member| member.key_id == *target) else {
            bail!("{target} is not enrolled");
        };
        let admins = self
            .list
            .iter()
            .filter(|member| member.role == MemberRole::Admin)
            .count();
        if member.role == MemberRole::Admin && admins == 1 {
            bail!(
                "cannot revoke the last admin: nobody could enroll or revoke, and an empty member list would let any local key approve"
            );
        }
        self.append(&signed)?;
        let target = target.clone();
        self.list.retain(|member| member.key_id != target);
        Ok(())
    }

    /// True when `key` is an enrolled admin.
    fn is_admin(&self, key: &str) -> bool {
        self.list
            .iter()
            .any(|member| member.key_id == key && member.role == MemberRole::Admin)
    }

    /// Append one signed line to the members file (mode 0600).
    ///
    /// # Errors
    /// Fails if the line cannot be encoded or written.
    fn append<T: Serialize>(&self, signed: &Signed<T>) -> Result<()> {
        let mut line = serde_json::to_vec(signed).context("cannot encode the members line")?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line))
            .with_context(|| format!("cannot write {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use cleanroom_proto::sign::generate_key;
    use cleanroom_proto::{Revocation, domain};

    use super::*;

    /// A fresh members file under the system temp directory, removed on drop.
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

    /// A person: key id and the record enrolling them as `role`. The daemon checks the
    /// signature before `Members` sees a record, so tests leave it empty.
    fn person(name: &str, role: MemberRole) -> (String, Signed<Member>) {
        let key = generate_key().expect("randomness").verifying_key();
        let id = key_id(&key);
        let member = Member {
            key_id: id.clone(),
            public_key: hex::encode(key.as_bytes()),
            name: name.to_owned(),
            role,
            enrolled_at: "2026-11-08T05:50:00Z".to_owned(),
        };
        (id, signed(domain::ENROLL, member))
    }

    fn signed<T>(domain: &str, body: T) -> Signed<T> {
        Signed {
            domain: domain.to_owned(),
            body,
            signer: String::new(),
            sig: String::new(),
        }
    }

    fn revocation(key_id: &str) -> Signed<Revocation> {
        signed(
            domain::REVOKE,
            Revocation {
                key_id: key_id.to_owned(),
                reason: "laptop lost".to_owned(),
                revoked_at: "2026-11-08T05:55:00Z".to_owned(),
            },
        )
    }

    /// An admin who enrolled themself, a second admin and a commander.
    fn team(path: &Path) -> (Members, String, String, String) {
        let mut members = Members::load(path).expect("empty members file");
        let (admin, admin_record) = person("Ada", MemberRole::Admin);
        let (second, second_record) = person("Bo", MemberRole::Admin);
        let (commander, commander_record) = person("Cy", MemberRole::Commander);
        for record in [admin_record, second_record, commander_record] {
            members.enroll(&admin, record).expect("admin enrolls");
        }
        (members, admin, second, commander)
    }

    #[test]
    fn a_revoked_commander_can_no_longer_approve_even_after_a_restart() {
        let scratch = Scratch::new("revoke");
        let (mut members, admin, _, commander) = team(&scratch.0);
        assert!(
            members.may_approve(&commander),
            "enrolled commanders approve"
        );

        members
            .revoke(&admin, revocation(&commander))
            .expect("an admin revokes");

        assert!(!members.may_approve(&commander), "revoked at once");
        let reloaded = Members::load(&scratch.0).expect("members file reloads");
        assert!(
            !reloaded.may_approve(&commander),
            "still revoked after a restart"
        );
        assert!(reloaded.may_approve(&admin), "the admin is unaffected");
    }

    #[test]
    fn only_admins_revoke_and_the_last_admin_stays() {
        let scratch = Scratch::new("revoke-rules");
        let (mut members, admin, second, commander) = team(&scratch.0);

        let refused = members
            .revoke(&commander, revocation(&admin))
            .expect_err("a commander cannot revoke");
        assert!(format!("{refused:#}").contains("admin"), "{refused:#}");
        members
            .revoke(&admin, revocation(&second))
            .expect("one admin revokes the other");
        let last = members
            .revoke(&admin, revocation(&admin))
            .expect_err("revoking the last admin would reopen bootstrap mode");
        assert!(format!("{last:#}").contains("last admin"), "{last:#}");
        assert!(
            !members.may_approve("sha256:stranger"),
            "nobody unenrolled may approve"
        );
    }

    #[test]
    fn re_enrolling_a_revoked_key_reinstates_it_in_order() {
        let scratch = Scratch::new("reinstate");
        let (mut members, admin, _, commander) = team(&scratch.0);
        let (_, again) = {
            let reloaded = Members::load(&scratch.0).expect("reload");
            let record = reloaded
                .list
                .iter()
                .find(|member| member.key_id == commander)
                .cloned()
                .expect("commander enrolled");
            (reloaded, signed(domain::ENROLL, record))
        };
        members
            .revoke(&admin, revocation(&commander))
            .expect("revoke");
        members.enroll(&admin, again).expect("re-enroll");

        let reloaded = Members::load(&scratch.0).expect("reload");
        assert!(
            reloaded.may_approve(&commander),
            "the later enrollment wins on reload"
        );
    }
}
