//! Every OS denial of the session, so the command center can pin them where they never scroll
//! away.
//!
//! One denial usually arrives twice: cleanroomd's `status` line (`OS denied hunter: …
//! (receipt #15)`), then the agent's `trace` with `outcome` denied. Both fold into one
//! [`Denial`]; whichever comes first creates it. cleanroomd keeping a measured record from an
//! agent (`OS kept the record: …`) is a denial too.

use cleanroom_proto::Role;
use jiff::{SignedDuration, Timestamp};

/// The status and trace of one denial arrive within this window of each other.
const PAIRING: SignedDuration = SignedDuration::from_secs(15);
/// How long the kernel banner stays pinned over the conversation.
pub(crate) const BANNER_FOR: SignedDuration = SignedDuration::from_secs(8);

/// What was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A command, refused by the stratum's grant (for example a read-only mount).
    Exec,
    /// A record update that would lower a flag cleanroomd measured.
    Record,
}

/// One denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Denial {
    /// What was denied.
    pub(crate) kind: Kind,
    /// Local `HH:MM:SS`.
    pub(crate) at: String,
    /// When it reached this console, for the banner.
    pub(crate) seen: Timestamp,
    /// The agent, when the name is a known role.
    pub(crate) role: Option<Role>,
    /// The agent as cleanroomd named it.
    pub(crate) who: String,
    /// The command (or record change) that was refused.
    pub(crate) command: String,
    /// Why, in cleanroomd's words.
    pub(crate) reason: String,
    /// The signed receipt that records it.
    pub(crate) receipt: Option<u64>,
    /// The agent's loop step, once its trace arrived.
    pub(crate) step: Option<u32>,
}

impl Denial {
    /// The reason in a word or two, for one-line traces: `read-only`, `no exec`, or the reason.
    pub(crate) fn short_reason(&self) -> String {
        short_reason(&self.reason)
    }
}

/// A denial as cleanroomd's `status` line reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reported {
    /// What was denied.
    pub(crate) kind: Kind,
    /// The agent's stratum name.
    pub(crate) who: String,
    /// The command or record change.
    pub(crate) command: String,
    /// Why.
    pub(crate) reason: String,
    /// The receipt.
    pub(crate) receipt: Option<u64>,
}

/// A denied step as the agent's `trace` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Traced {
    /// The agent.
    pub(crate) role: Role,
    /// Its loop step.
    pub(crate) step: u32,
    /// The command it asked for.
    pub(crate) command: String,
    /// The grant's reason.
    pub(crate) reason: String,
    /// The receipt, when the agent quoted it.
    pub(crate) receipt: Option<u64>,
}

/// The session's denials, oldest first.
#[derive(Debug, Clone, Default)]
pub(crate) struct Log {
    /// Every denial so far.
    items: Vec<Denial>,
}

impl Log {
    /// Every denial, oldest first.
    pub(crate) fn all(&self) -> &[Denial] {
        &self.items
    }

    /// How many denials there were.
    pub(crate) const fn len(&self) -> usize {
        self.items.len()
    }

    /// The newest denial while its banner is still up at `now`.
    pub(crate) fn banner(&self, now: Timestamp) -> Option<&Denial> {
        self.items
            .last()
            .filter(|denial| now.duration_since(denial.seen) < BANNER_FOR)
    }

    /// Fold in cleanroomd's status line. Returns the denial when it is new, so the caller can
    /// announce it once.
    pub(crate) fn reported(
        &mut self,
        reported: Reported,
        at: String,
        now: Timestamp,
    ) -> Option<&Denial> {
        let role = role_named(&reported.who);
        let pair = self.items.iter().rposition(|denial| {
            denial.kind == reported.kind
                && denial.who == reported.who
                && denial.receipt.is_none()
                && now.duration_since(denial.seen) < PAIRING
        });
        if let Some(index) = pair {
            if let Some(denial) = self.items.get_mut(index) {
                denial.receipt = reported.receipt;
            }
            return None;
        }
        self.items.push(Denial {
            kind: reported.kind,
            at,
            seen: now,
            role,
            who: reported.who,
            command: reported.command,
            reason: reported.reason,
            receipt: reported.receipt,
            step: None,
        });
        self.items.last()
    }

    /// Fold in an agent's denied trace step. Returns the denial when it is new.
    pub(crate) fn traced(&mut self, traced: Traced, at: String, now: Timestamp) -> Option<&Denial> {
        let pair = self.items.iter().rposition(|denial| {
            denial.kind == Kind::Exec
                && denial.role == Some(traced.role)
                && denial.step.is_none()
                && now.duration_since(denial.seen) < PAIRING
        });
        if let Some(index) = pair {
            if let Some(denial) = self.items.get_mut(index) {
                denial.step = Some(traced.step);
                denial.command = traced.command;
                denial.receipt = denial.receipt.or(traced.receipt);
            }
            return None;
        }
        self.items.push(Denial {
            kind: Kind::Exec,
            at,
            seen: now,
            role: Some(traced.role),
            who: role_name(traced.role).to_owned(),
            command: traced.command,
            reason: traced.reason,
            receipt: traced.receipt,
            step: Some(traced.step),
        });
        self.items.last()
    }

    /// Forget every denial (reset).
    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }
}

/// Read a cleanroomd status line that reports a denial; `None` for every other line.
pub(crate) fn parse_status(text: &str) -> Option<Reported> {
    if let Some(rest) = text.strip_prefix("OS denied ") {
        let (body, receipt) = split_receipt(rest);
        let (who, rest) = body.split_once(": `")?;
        let (command, reason) = rest.split_once("`: ")?;
        return Some(Reported {
            kind: Kind::Exec,
            who: who.to_owned(),
            command: command.strip_prefix("sh -c ").unwrap_or(command).to_owned(),
            reason: reason.to_owned(),
            receipt,
        });
    }
    let rest = text.strip_prefix("OS kept the record: ")?;
    let (body, receipt) = split_receipt(rest);
    let (who, rest) = body.split_once(" tried to lower ")?;
    let (change, reason) = rest.split_once(": ").unwrap_or((rest, ""));
    Some(Reported {
        kind: Kind::Record,
        who: who.to_owned(),
        command: format!("lower {change}"),
        reason: reason.to_owned(),
        receipt,
    })
}

/// Split a trailing ` (receipt #N)` off `text`.
pub(crate) fn split_receipt(text: &str) -> (&str, Option<u64>) {
    text.strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" (receipt #"))
        .and_then(|(body, number)| number.parse().ok().map(|seq| (body, Some(seq))))
        .unwrap_or((text, None))
}

/// The reason in a word or two: `read-only`, `no exec`, or the reason itself.
pub(crate) fn short_reason(reason: &str) -> String {
    let lower = reason.to_lowercase();
    if lower.contains("read_only") || lower.contains("read-only") {
        "read-only".to_owned()
    } else if lower.contains("no exec") {
        "no exec".to_owned()
    } else if lower.contains("measured") {
        "measured by cleanroomd".to_owned()
    } else {
        reason.to_owned()
    }
}

/// The role a stratum name stands for.
pub(crate) fn role_named(name: &str) -> Option<Role> {
    [
        Role::Lead,
        Role::Hunter,
        Role::Forensics,
        Role::Scribe,
        Role::Containment,
    ]
    .into_iter()
    .find(|role| role_name(*role) == name)
}

/// The stratum name of a role, as cleanroomd writes it.
pub(crate) const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Lead => "lead",
        Role::Hunter => "hunter",
        Role::Forensics => "forensics",
        Role::Scribe => "scribe",
        Role::Containment => "containment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + seconds).expect("fixed test time")
    }

    const STATUS: &str = "OS denied hunter: `sh -c rm -rf /evidence/*`: evidence is mounted read_only for hunter (receipt #15)";

    fn traced() -> Traced {
        Traced {
            role: Role::Hunter,
            step: 5,
            command: "rm -rf /evidence/*".to_owned(),
            reason: "evidence is mounted read_only for hunter".to_owned(),
            receipt: None,
        }
    }

    #[test]
    fn cleanroomd_status_lines_parse_into_denials() {
        let exec = parse_status(STATUS).expect("an exec denial");
        assert_eq!(exec.who, "hunter");
        assert_eq!(
            exec.command, "rm -rf /evidence/*",
            "the sh -c wrapper is dropped"
        );
        assert_eq!(exec.receipt, Some(15));
        assert_eq!(short_reason(&exec.reason), "read-only");

        let record = parse_status(
            "OS kept the record: scribe tried to lower payroll locked, accessed: measured yes by cleanroomd's integrity check; an agent cannot lower a measurement, only a commander can (receipt #23)",
        )
        .expect("a record denial");
        assert_eq!(record.kind, Kind::Record);
        assert_eq!(record.command, "lower payroll locked, accessed");
        assert_eq!(record.receipt, Some(23));
        assert!(
            parse_status("root debian admitted (receipt #3)").is_none(),
            "not a denial"
        );
    }

    #[test]
    fn the_status_and_the_trace_of_one_denial_fold_into_one() {
        let mut log = Log::default();
        let status = parse_status(STATUS).expect("an exec denial");
        assert!(
            log.reported(status, "04:39:30".to_owned(), at(0)).is_some(),
            "new"
        );
        assert!(
            log.traced(traced(), "04:39:30".to_owned(), at(1)).is_none(),
            "paired"
        );

        let [denial] = log.all() else {
            panic!("one denial, not two");
        };
        assert_eq!((denial.step, denial.receipt), (Some(5), Some(15)));

        assert!(
            log.traced(traced(), "04:41:00".to_owned(), at(90))
                .is_some(),
            "a later attempt is a new denial"
        );
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn the_banner_holds_for_eight_seconds() {
        let mut log = Log::default();
        assert!(
            log.traced(traced(), "04:39:30".to_owned(), at(0)).is_some(),
            "new"
        );
        assert!(log.banner(at(7)).is_some(), "still pinned after 7 s");
        assert!(log.banner(at(9)).is_none(), "gone after 8 s");
        assert_eq!(log.len(), 1, "the count stays");
    }
}
