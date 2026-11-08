//! Detects personal data and credentials in tool output, so the step can be routed to a local
//! model instead of the hosted API.
//!
//! The detector errs toward flagging: a false positive only keeps a step local, a false negative
//! sends raw evidence to a third party. Matched values are never reported, only their kinds.

use std::fmt::Write as _;

use regex::Regex;

/// A kind of sensitive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `123-45-6789`.
    SsnLike,
    /// 13–19 digits, optionally grouped by spaces or dashes, passing the Luhn check.
    CardLike,
    /// `password=…`, `DB_PASSWORD: …`, `"passwd": …`, `passphrase=…`.
    PasswordAssignment,
    /// A PEM or OpenSSH private-key header.
    PrivateKey,
    /// An AWS access key id or a labelled secret access key.
    AwsKey,
}

impl Kind {
    /// Short label for route reasons.
    const fn label(self) -> &'static str {
        match self {
            Self::SsnLike => "SSN-like number",
            Self::CardLike => "card-like number",
            Self::PasswordAssignment => "password assignment",
            Self::PrivateKey => "private key",
            Self::AwsKey => "AWS-style key",
        }
    }
}

/// How many matches of one kind a text contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hit {
    /// What was found.
    pub(crate) kind: Kind,
    /// How many times.
    pub(crate) count: usize,
}

/// Compiled detectors.
#[derive(Debug)]
pub(crate) struct Detector {
    /// SSN shape.
    ssn: Regex,
    /// Candidate card numbers, confirmed with Luhn.
    card: Regex,
    /// Password assignments.
    password: Regex,
    /// Private-key armor.
    private_key: Regex,
    /// AWS key ids and secret keys.
    aws: Regex,
}

impl Detector {
    /// Compile the patterns.
    ///
    /// # Errors
    /// Fails only if a built-in pattern does not compile.
    pub(crate) fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?,
            card: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b")?,
            password: Regex::new(r#"(?i)(?:password|passwd|passphrase)["']?\s*[=:]\s*\S"#)?,
            private_key: Regex::new(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")?,
            aws: Regex::new(
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            )?,
        })
    }

    /// Every kind of sensitive data in `text`, in a fixed order.
    pub(crate) fn scan(&self, text: &str) -> Vec<Hit> {
        let card_count = self
            .card
            .find_iter(text)
            .filter(|found| luhn_valid(found.as_str()))
            .count();
        [
            (Kind::SsnLike, self.ssn.find_iter(text).count()),
            (Kind::CardLike, card_count),
            (
                Kind::PasswordAssignment,
                self.password.find_iter(text).count(),
            ),
            (Kind::PrivateKey, self.private_key.find_iter(text).count()),
            (Kind::AwsKey, self.aws.find_iter(text).count()),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(kind, count)| Hit { kind, count })
        .collect()
    }
}

/// `2 SSN-like numbers, 1 password assignment`.
pub(crate) fn describe(hits: &[Hit]) -> String {
    let mut text = String::new();
    for (index, hit) in hits.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        let plural = if hit.count == 1 { "" } else { "s" };
        // Writing to a String cannot fail.
        if write!(text, "{} {}{plural}", hit.count, hit.kind.label()).is_err() {
            break;
        }
    }
    text
}

/// Luhn checksum over the digits of `candidate`, ignoring separators.
fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(position, &digit)| {
            if position % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    (13..=19).contains(&digits.len()) && sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<Kind> {
        Detector::new()
            .expect("built-in patterns compile")
            .scan(text)
            .into_iter()
            .map(|hit| hit.kind)
            .collect()
    }

    #[test]
    fn finds_personal_data_and_credentials() {
        assert_eq!(
            kinds("emp_id,ssn\n1042,078-05-1120\n"),
            [Kind::SsnLike],
            "SSN column"
        );
        assert_eq!(
            kinds("card 4111 1111 1111 1111 exp 12/29"),
            [Kind::CardLike],
            "grouped Visa test number"
        );
        assert_eq!(
            kinds("DB_PASSWORD = hunter2"),
            [Kind::PasswordAssignment],
            "env-style password"
        );
        assert_eq!(
            kinds("password:Spring2026!"),
            [Kind::PasswordAssignment],
            "colon separator"
        );
        assert_eq!(
            kinds("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA="),
            [Kind::PrivateKey],
            "OpenSSH key"
        );
        assert_eq!(
            kinds("-----BEGIN RSA PRIVATE KEY-----"),
            [Kind::PrivateKey],
            "PEM RSA key"
        );
        assert_eq!(
            kinds("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"),
            [Kind::AwsKey],
            "key id"
        );
        assert_eq!(
            kinds("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            [Kind::AwsKey],
            "secret key"
        );
    }

    #[test]
    fn counts_each_kind() {
        let hits = Detector::new()
            .expect("built-in patterns compile")
            .scan("123-45-6789 and 987-65-4321, password=x");
        assert_eq!(
            describe(&hits),
            "2 SSN-like numbers, 1 password assignment",
            "route reason lists kinds and counts"
        );
    }

    #[test]
    fn ordinary_evidence_is_not_flagged() {
        let log = "\
Nov  7 18:02:11 acme-fs sshd[811]: Accepted password for backup from 203.0.113.45 port 51122 ssh2
-rw-r--r-- 1 root root 48211 Nov  7 18:04 payroll_2026Q3.csv.lockbyte
2026-11-07T18:04:09Z lockbyte: encrypted 1342 files
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /evidence/note.txt
call 555-123-4567 or order 1234567890123 (not a card)
the password policy requires 12 characters";
        assert_eq!(
            kinds(log),
            [],
            "logs, listings, hashes, phones and prose stay hosted"
        );
    }
}
