//! `cleanroomd probe`: prove a stratum's walls from inside it. Each wall is one command run as
//! the stratum's agent under its grant, so each result comes with a signed receipt.

use cleanroom_proto::{ExecOutcome, ExecResult};

/// Variables a stratum's environment may hold: the ones cleanroomd sets, and `PWD`, which
/// bubblewrap sets from `--chdir`. It clears everything else.
const ALLOWED_ENV: &[&str] = &["HOME", "LANG", "TMPDIR", "PATH", "PWD"];

/// One wall of a stratum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wall {
    /// No network interface besides loopback.
    Network,
    /// No effective capabilities.
    Capabilities,
    /// No nested user namespaces.
    UserNamespaces,
    /// Nothing in the environment but the variables cleanroomd sets: no API keys.
    Environment,
    /// The evidence is read-only, enforced by the kernel.
    EvidenceReadOnly,
    /// The host user's home directory is not visible.
    HostHome,
}

impl Wall {
    /// Every wall, in the order the probe checks them.
    pub(crate) const ALL: [Self; 6] = [
        Self::Network,
        Self::Capabilities,
        Self::UserNamespaces,
        Self::Environment,
        Self::EvidenceReadOnly,
        Self::HostHome,
    ];

    /// What the wall promises.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Network => "no network",
            Self::Capabilities => "no capabilities",
            Self::UserNamespaces => "no nested user namespaces",
            Self::Environment => "no secrets in the environment",
            Self::EvidenceReadOnly => "evidence read-only",
            Self::HostHome => "host home not visible",
        }
    }

    /// The command that tests the wall from inside; `host_home` is the invoking user's home.
    pub(crate) fn argv(self, host_home: &str) -> Vec<String> {
        let argv: &[&str] = match self {
            Self::Network => &[
                "sh",
                "-c",
                "tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '",
            ],
            Self::Capabilities => &["grep", "CapEff", "/proc/self/status"],
            Self::UserNamespaces => &["unshare", "-U", "true"],
            Self::Environment => &["env"],
            Self::EvidenceReadOnly => &["touch", "/evidence/acme-fs/.cleanroom-probe"],
            Self::HostHome => &["test", "-e", host_home],
        };
        argv.iter().map(|&arg| arg.to_owned()).collect()
    }

    /// Whether `result` shows the wall holding: `Ok(detail)` or `Err(what broke)`. Never echoes
    /// a variable's value.
    pub(crate) fn judge(self, result: &ExecResult) -> Result<String, String> {
        let succeeded = matches!(result.outcome, ExecOutcome::Exited { code: 0 });
        let refused = matches!(
            result.outcome,
            ExecOutcome::Exited { code } if code != 0
        );
        match self {
            Self::Network => {
                if !succeeded {
                    return Err("could not list the interfaces".to_owned());
                }
                let others: Vec<&str> =
                    lines(&result.stdout).filter(|name| *name != "lo").collect();
                if others.is_empty() {
                    Ok("only lo".to_owned())
                } else {
                    Err(format!("interfaces besides lo: {}", others.join(", ")))
                }
            }
            Self::Capabilities => {
                let effective = lines(&result.stdout)
                    .find_map(|line| line.strip_prefix("CapEff:"))
                    .map(str::trim);
                match effective {
                    Some(mask) if !mask.is_empty() && mask.chars().all(|c| c == '0') => {
                        Ok("CapEff 0".to_owned())
                    }
                    Some(mask) => Err(format!("effective capabilities {mask}")),
                    None => Err("could not read CapEff".to_owned()),
                }
            }
            Self::UserNamespaces => {
                if refused || matches!(result.outcome, ExecOutcome::Denied { .. }) {
                    Ok("unshare -U refused".to_owned())
                } else if succeeded {
                    Err("a nested user namespace opened".to_owned())
                } else {
                    Err("unshare -U timed out".to_owned())
                }
            }
            Self::Environment => {
                if !succeeded {
                    return Err("could not list the environment".to_owned());
                }
                let names: Vec<&str> = lines(&result.stdout)
                    .map(|line| line.split_once('=').map_or(line, |(name, _)| name))
                    .collect();
                let extra: Vec<&str> = names
                    .iter()
                    .copied()
                    .filter(|name| !ALLOWED_ENV.contains(name))
                    .collect();
                if extra.is_empty() {
                    Ok(format!("only {}", names.join(", ")))
                } else {
                    Err(format!("unexpected variables: {}", extra.join(", ")))
                }
            }
            Self::EvidenceReadOnly => match &result.outcome {
                ExecOutcome::Denied { .. } => Ok("write denied by the kernel".to_owned()),
                ExecOutcome::Exited { code: 0 } => Err("the write succeeded".to_owned()),
                ExecOutcome::Exited { .. } | ExecOutcome::TimedOut => {
                    Err("the write failed without a read-only denial".to_owned())
                }
            },
            Self::HostHome => {
                if refused {
                    Ok("absent".to_owned())
                } else if succeeded {
                    Err("the host home is visible".to_owned())
                } else {
                    Err("could not test the host home".to_owned())
                }
            }
        }
    }
}

/// Non-empty trimmed lines.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(code: i32, stdout: &str) -> ExecResult {
        ExecResult {
            outcome: ExecOutcome::Exited { code },
            stdout: stdout.to_owned(),
            stderr: String::new(),
            truncated: false,
            receipt_seq: 7,
        }
    }

    fn denied() -> ExecResult {
        ExecResult {
            outcome: ExecOutcome::Denied {
                reason: "evidence is mounted read_only for hunter".to_owned(),
            },
            ..exited(1, "")
        }
    }

    #[test]
    fn only_loopback_means_no_network() {
        assert!(Wall::Network.judge(&exited(0, "lo\n")).is_ok());
        let leak = Wall::Network.judge(&exited(0, "lo\neth0\n"));
        assert!(leak.is_err_and(|why| why.contains("eth0")));
    }

    #[test]
    fn any_effective_capability_fails() {
        assert!(
            Wall::Capabilities
                .judge(&exited(0, "CapEff:\t0000000000000000\n"))
                .is_ok()
        );
        assert!(
            Wall::Capabilities
                .judge(&exited(0, "CapEff:\t0000000000200000\n"))
                .is_err()
        );
    }

    #[test]
    fn a_nested_user_namespace_that_opens_fails() {
        assert!(Wall::UserNamespaces.judge(&exited(1, "")).is_ok());
        assert!(Wall::UserNamespaces.judge(&exited(0, "")).is_err());
    }

    #[test]
    fn a_secret_in_the_environment_fails() {
        let clean = "HOME=/tmp\nLANG=C.UTF-8\nTMPDIR=/tmp\nPATH=/usr/bin:/bin\nPWD=/tmp\n";
        assert!(Wall::Environment.judge(&exited(0, clean)).is_ok());
        let leaked = format!("{clean}NVIDIA_API_KEY=nvapi-x\n");
        let verdict = Wall::Environment.judge(&exited(0, &leaked));
        assert!(
            verdict.is_err_and(|why| why.contains("NVIDIA_API_KEY") && !why.contains("nvapi")),
            "names the variable, never prints its value"
        );
    }

    #[test]
    fn only_a_kernel_denial_proves_evidence_read_only() {
        assert!(Wall::EvidenceReadOnly.judge(&denied()).is_ok());
        assert!(Wall::EvidenceReadOnly.judge(&exited(0, "")).is_err());
        assert!(
            Wall::EvidenceReadOnly.judge(&exited(1, "")).is_err(),
            "a failure that is not a read-only denial proves nothing"
        );
    }

    #[test]
    fn a_visible_host_home_fails() {
        assert!(Wall::HostHome.judge(&exited(1, "")).is_ok());
        assert!(Wall::HostHome.judge(&exited(0, "")).is_err());
    }
}
