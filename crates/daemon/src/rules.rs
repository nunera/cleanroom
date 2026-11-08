//! Detection rules written by agents. An investigator submits a YARA rule; cleanroomd runs it in
//! a sandbox over the clean seed files and over the evidence, and admits it into `/rules` only if
//! it compiles, matches no clean file and matches some evidence. The model writes the rule; the
//! OS decides whether it ships.

use crate::strata::{Captured, RULE_CHECK_SEED};

/// Longest rule name.
const NAME_MAX: usize = 40;
/// Largest rule source accepted.
pub(crate) const SOURCE_MAX: usize = 16 * 1024;
/// Clean-file or error lines quoted in a rejection at most.
const QUOTE_LIMIT: usize = 4;

/// A rule name becomes a file name under `/rules`: lowercase letters, digits, `-` and `_`.
///
/// # Errors
/// Says what is wrong with `name`.
pub(crate) fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(format!("a rule name has 1 to {NAME_MAX} characters"));
    }
    if name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err("a rule name uses only lowercase letters, digits, - and _".to_owned())
    }
}

/// Decide from `yara -r <rule> /seed` (`seed`) and `yara -r <rule> /evidence` (`evidence`):
/// the evidence files the rule matches, or why it is rejected.
///
/// # Errors
/// The rule does not compile, matches a clean seed file, matches no evidence, or a scan did not
/// finish.
pub(crate) fn judge(seed: &Captured, evidence: &Captured) -> Result<Vec<String>, String> {
    if seed.timed_out || evidence.timed_out {
        return Err("the rule check timed out".to_owned());
    }
    if seed.code != Some(0) {
        return Err(format!(
            "the rule does not compile: {}",
            quote(&seed.stderr).unwrap_or_else(|| "yara failed without a message".to_owned())
        ));
    }
    let clean: Vec<&str> = matched(&seed.stdout)
        .map(|path| {
            path.strip_prefix(RULE_CHECK_SEED)
                .map_or(path, |rest| rest.trim_start_matches('/'))
        })
        .collect();
    if !clean.is_empty() {
        return Err(format!(
            "the rule matches {} clean file(s) from before the attack: {}",
            clean.len(),
            shown(&clean)
        ));
    }
    if evidence.code != Some(0) {
        return Err(format!(
            "scanning the evidence failed: {}",
            quote(&evidence.stderr).unwrap_or_else(|| "no message".to_owned())
        ));
    }
    let hits: Vec<String> = matched(&evidence.stdout).map(str::to_owned).collect();
    if hits.is_empty() {
        return Err(
            "the rule matches no evidence, so it detects nothing from this attack".to_owned(),
        );
    }
    Ok(hits)
}

/// The file paths in `yara` output lines (`<rule> <path>`).
fn matched(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .lines()
        .filter_map(|line| line.trim().split_once(' ').map(|(_, path)| path.trim()))
        .filter(|path| !path.is_empty())
}

/// The first lines of `text`, or `None` when it is blank.
fn quote(text: &str) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(QUOTE_LIMIT)
        .collect();
    (!lines.is_empty()).then(|| lines.join("; "))
}

/// Up to [`QUOTE_LIMIT`] items, then a count of the rest.
fn shown(items: &[&str]) -> String {
    let mut text = items[..items.len().min(QUOTE_LIMIT)].join(", ");
    if items.len() > QUOTE_LIMIT {
        text.push_str(&format!(" and {} more", items.len() - QUOTE_LIMIT));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ran(code: i32, stdout: &str, stderr: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            ..Captured::default()
        }
    }

    #[test]
    fn rule_names_are_short_lowercase_slugs() {
        assert!(check_name("lockstar_note").is_ok());
        assert!(check_name("lockstar-2").is_ok());
        for bad in ["", "../escape", "Lockstar", "a b", &"x".repeat(41)] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_rule_that_does_not_compile_is_rejected_with_yaras_error() {
        let seed = ran(
            1,
            "",
            "error: rule \"x\" in /candidate.yar(3): syntax error\n",
        );
        let verdict = judge(&seed, &ran(1, "", ""));
        assert!(
            verdict
                .is_err_and(|why| why.contains("does not compile") && why.contains("syntax error"))
        );
    }

    /// A detection that fires on the company's own clean files would page responders for nothing
    /// and could hide the real hits: the OS refuses it and names the files.
    #[test]
    fn a_rule_that_matches_a_clean_file_is_rejected() {
        let seed = ran(0, "Lockstar_Any /seed/payroll.csv\n", "");
        let evidence = ran(0, "Lockstar_Any /evidence/acme-fs/payroll.csv.locked\n", "");
        let verdict = judge(&seed, &evidence);
        assert!(verdict.is_err_and(|why| why.contains("clean") && why.contains("payroll.csv")));
    }

    #[test]
    fn a_rule_that_matches_no_evidence_is_rejected() {
        let verdict = judge(&ran(0, "", ""), &ran(0, "", ""));
        assert!(verdict.is_err_and(|why| why.contains("no evidence")));
    }

    #[test]
    fn a_clean_rule_that_finds_evidence_is_admitted_with_its_matches() {
        let evidence = ran(
            0,
            "Lockstar_Note /evidence/acme-fs/README_RESTORE_FILES.txt\nLockstar_Note /evidence/logs/syslog\n",
            "",
        );
        assert_eq!(
            judge(&ran(0, "", ""), &evidence),
            Ok(vec![
                "/evidence/acme-fs/README_RESTORE_FILES.txt".to_owned(),
                "/evidence/logs/syslog".to_owned(),
            ])
        );
    }

    #[test]
    fn a_scan_that_timed_out_proves_nothing() {
        let stuck = Captured {
            timed_out: true,
            ..Captured::default()
        };
        assert!(judge(&stuck, &ran(0, "", "")).is_err());
    }
}
