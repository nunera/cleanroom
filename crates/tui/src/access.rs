//! Who is enrolled, as far as this console can know.
//!
//! cleanroomd has no operation that lists members, so the roster holds what this session saw:
//! enrollments and revocations this console sent and cleanroomd accepted, and the `status` lines
//! cleanroomd publishes for every enrollment and revocation ("enrolled Ada (admin): sha256:…
//! (receipt #31)", "revoked sha256:…: laptop lost (receipt #33)").

use cleanroom_proto::{KeyId, MemberRole};

use crate::denials::split_receipt;

/// Where a member stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Enrolled: approves (commanders and admins), enrolls and revokes (admins).
    Enrolled,
    /// Revoked: no longer approves, enrolls or revokes.
    Revoked,
}

/// One member this session knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enrollment {
    /// `sha256:` of the member's public key.
    pub(crate) key_id: KeyId,
    /// The raw public key, when this console enrolled it (so it can enroll it again).
    pub(crate) public_key: Option<String>,
    /// Display name.
    pub(crate) name: Option<String>,
    /// Role.
    pub(crate) role: Option<MemberRole>,
    /// Enrolled or revoked.
    pub(crate) standing: Standing,
    /// The receipt of the latest change, when known.
    pub(crate) receipt: Option<u64>,
}

/// The members this session knows about, in first-seen order.
#[derive(Debug, Clone, Default)]
pub(crate) struct Roster {
    /// Every member seen so far.
    members: Vec<Enrollment>,
}

impl Roster {
    /// Every known member.
    pub(crate) fn all(&self) -> &[Enrollment] {
        &self.members
    }

    /// The member with `key_id`.
    pub(crate) fn get(&self, key_id: &str) -> Option<&Enrollment> {
        self.members.iter().find(|member| member.key_id == key_id)
    }

    /// Record an enrollment, merging with what is already known about the key.
    pub(crate) fn enrolled(&mut self, enrollment: Enrollment) {
        match self
            .members
            .iter_mut()
            .find(|member| member.key_id == enrollment.key_id)
        {
            Some(known) => {
                known.public_key = enrollment.public_key.or_else(|| known.public_key.take());
                known.name = enrollment.name.or_else(|| known.name.take());
                known.role = enrollment.role.or(known.role);
                known.standing = Standing::Enrolled;
                known.receipt = enrollment.receipt.or(known.receipt);
            }
            None => self.members.push(enrollment),
        }
    }

    /// Record a revocation of `key_id`.
    pub(crate) fn revoked(&mut self, key_id: &str, receipt: Option<u64>) {
        match self
            .members
            .iter_mut()
            .find(|member| member.key_id == key_id)
        {
            Some(known) => {
                known.standing = Standing::Revoked;
                known.receipt = receipt.or(known.receipt);
            }
            None => self.members.push(Enrollment {
                key_id: key_id.to_owned(),
                public_key: None,
                name: None,
                role: None,
                standing: Standing::Revoked,
                receipt,
            }),
        }
    }

    /// Fold in a cleanroomd status line about members; false for every other line.
    pub(crate) fn status(&mut self, text: &str) -> bool {
        if let Some(rest) = text.strip_prefix("enrolled ") {
            let (body, receipt) = split_receipt(rest);
            let Some((label, key_id)) = body.rsplit_once(": ") else {
                return false;
            };
            let (name, role) = label
                .strip_suffix(')')
                .and_then(|label| label.rsplit_once(" ("))
                .map_or((label, None), |(name, role)| (name, role_named(role)));
            self.enrolled(Enrollment {
                key_id: key_id.to_owned(),
                public_key: None,
                name: Some(name.to_owned()),
                role,
                standing: Standing::Enrolled,
                receipt,
            });
            return true;
        }
        if let Some(rest) = text.strip_prefix("revoked ") {
            let (body, receipt) = split_receipt(rest);
            let key_id = body.split_once(": ").map_or(body, |(key_id, _)| key_id);
            if key_id.starts_with("sha256:") {
                self.revoked(key_id, receipt);
                return true;
            }
        }
        false
    }
}

/// Lowercase name of a member role, as on the wire.
pub(crate) const fn role_word(role: MemberRole) -> &'static str {
    match role {
        MemberRole::Admin => "admin",
        MemberRole::Commander => "commander",
        MemberRole::Responder => "responder",
        MemberRole::Observer => "observer",
    }
}

/// Every member role, in the order the enroll form cycles through them.
pub(crate) const MEMBER_ROLES: [MemberRole; 4] = [
    MemberRole::Admin,
    MemberRole::Commander,
    MemberRole::Responder,
    MemberRole::Observer,
];

/// The member role named `word`.
fn role_named(word: &str) -> Option<MemberRole> {
    MEMBER_ROLES
        .into_iter()
        .find(|role| role_word(*role) == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sha256:5f2a0000000000000000000000000000000000000000000000000000000000aa";

    #[test]
    fn cleanroomd_member_lines_build_the_roster() {
        let mut roster = Roster::default();
        assert!(roster.status(&format!("enrolled Ada Admin (admin): {KEY} (receipt #31)")));
        let ada = roster.get(KEY).expect("Ada is on the roster");
        assert_eq!(ada.name.as_deref(), Some("Ada Admin"));
        assert_eq!((ada.role, ada.receipt), (Some(MemberRole::Admin), Some(31)));

        assert!(roster.status(&format!("revoked {KEY}: laptop lost (receipt #33)")));
        let ada = roster.get(KEY).expect("Ada stays listed");
        assert_eq!((ada.standing, ada.receipt), (Standing::Revoked, Some(33)));
        assert_eq!(ada.name.as_deref(), Some("Ada Admin"), "the name survives");

        assert!(!roster.status("receipt log verified: 28 receipts, chain intact"));
    }
}
