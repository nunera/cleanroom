//! Citation checks: when an agent publishes a finding, cleanroomd checks every `/evidence/...`
//! path it cites against the real evidence (does it exist?) and against the commands it ran for
//! that agent (did one of them touch it, or a directory above it?). The result is a status line;
//! the finding itself is never dropped. A model that invents a source, or cites a file it never
//! opened, is named in the record.

/// What every cited path starts with.
const EVIDENCE_ROOT: &str = "/evidence";
/// Characters that end a path inside an evidence line.
const PATH_END: &[char] = &[',', ';', '(', ')', '[', ']', '"', '\'', '`'];

/// One checked citation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Citation {
    /// The cited path, as the agent wrote it.
    pub(crate) path: String,
    /// It exists in the evidence.
    pub(crate) exists: bool,
    /// A command cleanroomd ran for the agent named it or a directory above it.
    pub(crate) touched: bool,
}

/// Every distinct `/evidence/...` path in `evidence`, in order.
pub(crate) fn cited_paths(evidence: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for line in evidence {
        let mut rest = line.as_str();
        while let Some(start) = rest.find(&format!("{EVIDENCE_ROOT}/")) {
            let tail = &rest[start..];
            let end = tail
                .find(|c: char| c.is_whitespace() || PATH_END.contains(&c))
                .unwrap_or(tail.len());
            let path = tail[..end].trim_end_matches(['.', ':', '/']);
            if !path.is_empty() && !paths.iter().any(|seen| seen == path) {
                paths.push(path.to_owned());
            }
            rest = &tail[end..];
        }
    }
    paths
}

/// Whether one of `commands` named `path` or a directory above it as a whole argument.
pub(crate) fn touched(path: &str, commands: &[String]) -> bool {
    commands.iter().any(|command| {
        command.split_whitespace().any(|word| {
            let word = word.trim_matches(['"', '\'']).trim_end_matches('/');
            !word.is_empty()
                && word.starts_with(EVIDENCE_ROOT)
                && (path == word || path.starts_with(&format!("{word}/")))
        })
    })
}

/// The status line for `role`'s finding, or `None` when it cites no evidence path.
pub(crate) fn status(role: &str, citations: &[Citation]) -> Option<String> {
    if citations.is_empty() {
        return None;
    }
    let held = citations
        .iter()
        .filter(|citation| citation.exists && citation.touched)
        .count();
    let problems: Vec<String> = citations
        .iter()
        .filter_map(|citation| {
            if !citation.exists && citation.path.contains(['*', '?']) {
                Some(format!("{} is a wildcard, not a file", citation.path))
            } else if !citation.exists {
                Some(format!("{} does not exist", citation.path))
            } else if !citation.touched {
                Some(format!("{} was never touched by {role}", citation.path))
            } else {
                None
            }
        })
        .collect();
    let total = citations.len();
    Some(if problems.is_empty() {
        format!(
            "citations in {role}'s finding: all {total} cited evidence paths exist and were touched by {role}'s commands"
        )
    } else {
        format!(
            "citations in {role}'s finding: {held} of {total} hold up; {}",
            problems.join("; ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evidence strings as agents actually wrote them in live runs.
    #[test]
    fn cited_paths_are_the_evidence_paths_in_each_line() {
        let evidence = [
            "/evidence/logs/auth.log - SSH brute-force from 203.0.113.45, backup login at 04:51:21"
                .to_owned(),
            "/evidence/yara_scan (Lockstar_Locked_File matches)".to_owned(),
            "cleanroomd integrity check against the hashes taken at seeding".to_owned(),
            "/evidence/acme-fs/payroll.csv.locked, /evidence/dropbox/payroll.csv".to_owned(),
        ];
        assert_eq!(
            cited_paths(&evidence),
            [
                "/evidence/logs/auth.log",
                "/evidence/yara_scan",
                "/evidence/acme-fs/payroll.csv.locked",
                "/evidence/dropbox/payroll.csv",
            ]
        );
    }

    /// A path counts as touched when a command named it or a directory above it (a recursive
    /// grep or scan of `/evidence/logs` reads `auth.log`), and not when a command merely named a
    /// sibling.
    #[test]
    fn a_path_is_touched_by_a_command_on_it_or_on_a_directory_above_it() {
        let commands = [
            "grep -rnE -e Accepted /evidence/logs".to_owned(),
            "head -c 65536 /evidence/acme-fs/README_RESTORE_FILES.txt".to_owned(),
        ];
        assert!(touched("/evidence/logs/auth.log", &commands));
        assert!(touched(
            "/evidence/acme-fs/README_RESTORE_FILES.txt",
            &commands
        ));
        assert!(!touched("/evidence/acme-fs/payroll.csv.locked", &commands));
        assert!(
            !touched("/evidence/logs-old/auth.log", &commands),
            "a prefix is not a parent"
        );
    }

    #[test]
    fn the_status_line_names_what_does_not_hold_up() {
        let checked = [
            Citation {
                path: "/evidence/logs/auth.log".to_owned(),
                exists: true,
                touched: true,
            },
            Citation {
                path: "/evidence/yara_scan".to_owned(),
                exists: false,
                touched: false,
            },
            Citation {
                path: "/evidence/dropbox/payroll.csv".to_owned(),
                exists: true,
                touched: false,
            },
        ];
        let line = status("hunter", &checked).expect("a line");
        assert!(line.contains("1 of 3"), "{line}");
        assert!(
            line.contains("/evidence/yara_scan does not exist"),
            "{line}"
        );
        assert!(
            line.contains("/evidence/dropbox/payroll.csv was never touched by hunter"),
            "{line}"
        );
        assert!(
            status("hunter", &[]).is_none(),
            "nothing cited, nothing to say"
        );
        let wildcard = Citation {
            path: "/evidence/acme-fs/contracts/*.locked".to_owned(),
            exists: false,
            touched: false,
        };
        let line = status("forensics", &[wildcard]).expect("a line");
        assert!(
            line.contains("/evidence/acme-fs/contracts/*.locked is a wildcard, not a file"),
            "a pattern is named as a pattern: {line}"
        );
    }
}
