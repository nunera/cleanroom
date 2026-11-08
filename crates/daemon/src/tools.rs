//! Tool admission: the policy that decides a `request_tool`, building granted tools from pinned
//! nixpkgs, and the tools each role currently holds.
//!
//! An allowlisted tool requested from the pinned nixpkgs is admitted without a human; any other
//! well-formed nix reference waits for a commander's signature; anything else is denied. A
//! granted tool's `bin` directories are searched first inside the role's stratum, with the Nix
//! store bound read-only.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{Role, ToolDecision, ToolRequest, ToolSource};
use serde_json::Value;
use tokio::process::Command;

use crate::lock;

/// Tools admitted without a human when requested from the pinned nixpkgs.
pub(crate) const ALLOWLIST: [&str; 5] = ["yara", "volatility3", "tshark", "file", "binutils"];
/// Tools a role holds from the start: Hunter works logs and YARA (the grants table).
pub(crate) const BASELINE: [(Role, &str); 1] = [(Role::Hunter, "yara")];
/// Longest a tool build may take.
const BUILD_TIMEOUT: Duration = Duration::from_mins(15);
/// Longest flake reference accepted.
const MAX_REF: usize = 512;

/// Which nixpkgs counts as pinned.
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    /// Flake reference prefix, for example `github:NixOS/nixpkgs/<rev>`.
    nixpkgs: String,
}

impl Policy {
    /// `CLEANROOM_NIXPKGS` (the variable the agents read too), else the nixpkgs pin in the
    /// repository's `flake.lock`.
    ///
    /// # Errors
    /// Fails if neither names a nixpkgs revision.
    pub(crate) fn load(repo: &Path) -> Result<Self> {
        if let Some(nixpkgs) = std::env::var("CLEANROOM_NIXPKGS")
            .ok()
            .filter(|value| !value.is_empty())
        {
            return Ok(Self { nixpkgs });
        }
        let path = repo.join("flake.lock");
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let lock: Value = serde_json::from_str(&text)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let locked = lock
            .pointer("/nodes/nixpkgs/locked")
            .with_context(|| format!("{} has no locked nixpkgs", path.display()))?;
        let field = |name: &str| locked.get(name).and_then(Value::as_str);
        if let (Some("github"), Some(owner), Some(repo), Some(rev)) =
            (field("type"), field("owner"), field("repo"), field("rev"))
        {
            return Ok(Self {
                nixpkgs: format!("github:{owner}/{repo}/{rev}"),
            });
        }
        bail!(
            "{} pins nixpkgs in a form cleanroomd does not read",
            path.display()
        )
    }

    /// `<pinned nixpkgs>#<tool>`.
    pub(crate) fn pinned(&self, tool: &str) -> String {
        format!("{}#{tool}", self.nixpkgs)
    }

    /// Decide a request on policy alone.
    pub(crate) fn decide(&self, request: &ToolRequest) -> ToolDecision {
        if !valid_name(&request.tool) {
            return ToolDecision::Denied {
                reason: format!("`{}` is not a valid tool name", request.tool),
            };
        }
        match &request.source {
            ToolSource::Oci { .. } => ToolDecision::Denied {
                reason: "only nix tool sources can be materialized".to_owned(),
            },
            ToolSource::Nix { flake_ref } if !valid_ref(flake_ref) => ToolDecision::Denied {
                reason: format!("`{flake_ref}` is not a flake reference cleanroomd will build"),
            },
            ToolSource::Nix { flake_ref }
                if *flake_ref == self.pinned(&request.tool)
                    && ALLOWLIST.contains(&request.tool.as_str()) =>
            {
                ToolDecision::AutoAllowed {
                    rule: format!("allowlist: {} from pinned {}", request.tool, self.nixpkgs),
                }
            }
            ToolSource::Nix { .. } => ToolDecision::Pending,
        }
    }
}

/// A nixpkgs attribute name, as the agents' schema allows: `[a-z0-9][a-z0-9._+-]{0,63}`.
fn valid_name(tool: &str) -> bool {
    let mut chars = tool.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && tool.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._+-".contains(c))
}

/// A flake reference with no option prefix, whitespace or shell metacharacters.
fn valid_ref(flake_ref: &str) -> bool {
    !flake_ref.is_empty()
        && flake_ref.len() <= MAX_REF
        && !flake_ref.starts_with('-')
        && flake_ref.contains('#')
        && flake_ref
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":/._#+-?=&".contains(c))
}

/// Build `flake_ref` and return the `bin` directories of its outputs.
///
/// Builds run with `--impure` and `NIXPKGS_ALLOW_UNFREE=1`: the pinned nixpkgs marks
/// volatility3 unfree (license unknown), and the policy above already decided the tool.
///
/// # Errors
/// Fails if `nix build` fails or times out, or no output has a `bin` directory.
pub(crate) async fn materialize(flake_ref: &str) -> Result<Vec<PathBuf>> {
    let build = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--no-link",
            "--print-out-paths",
            "--impure",
            flake_ref,
        ])
        .env("NIXPKGS_ALLOW_UNFREE", "1")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(BUILD_TIMEOUT, build)
        .await
        .with_context(|| {
            format!(
                "nix build {flake_ref} took longer than {} min",
                BUILD_TIMEOUT.as_secs() / 60
            )
        })?
        .context("cannot run nix")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no error output");
        bail!("nix build {flake_ref} failed: {}", last.trim());
    }
    let bins: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| Path::new(line.trim()).join("bin"))
        .filter(|bin| bin.starts_with("/nix/store/") && bin.is_dir())
        .collect();
    if bins.is_empty() {
        bail!("{flake_ref} has no output with a bin directory");
    }
    Ok(bins)
}

/// A tool materialized into a role's stratum.
#[derive(Debug, Clone)]
pub(crate) struct Granted {
    /// Tool name.
    pub(crate) name: String,
    /// Its `bin` directories in the Nix store.
    pub(crate) bins: Vec<PathBuf>,
    /// Part of the role's standing grant, kept across resets.
    pub(crate) baseline: bool,
}

/// The tools each role holds.
#[derive(Debug, Default)]
pub(crate) struct Grants {
    /// `(role, tool)` pairs; a role holds each tool name once.
    held: Mutex<Vec<(Role, Granted)>>,
}

impl Grants {
    /// Grant `tool` to `role`, replacing an earlier grant of the same name.
    pub(crate) fn add(&self, role: Role, tool: Granted) {
        let mut held = lock(&self.held);
        held.retain(|(holder, existing)| *holder != role || existing.name != tool.name);
        held.push((role, tool));
    }

    /// The tools `role` holds.
    pub(crate) fn of(&self, role: Role) -> Vec<Granted> {
        lock(&self.held)
            .iter()
            .filter(|(holder, _)| *holder == role)
            .map(|(_, tool)| tool.clone())
            .collect()
    }

    /// Drop everything granted during the incident; standing grants stay.
    pub(crate) fn reset(&self) {
        lock(&self.held).retain(|(_, tool)| tool.baseline);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "github:NixOS/nixpkgs/c56a87d8e41ce69bd2af57eb35dcc117a9dfca33";

    fn policy() -> Policy {
        Policy {
            nixpkgs: PIN.to_owned(),
        }
    }

    fn request(tool: &str, source: ToolSource) -> ToolRequest {
        ToolRequest {
            id: "INC-1-forensics-tool-1".into(),
            from: Role::Forensics,
            stratum: "forensics".into(),
            tool: tool.into(),
            source,
            reason: "memory image analysis".into(),
        }
    }

    fn nix(flake_ref: &str) -> ToolSource {
        ToolSource::Nix {
            flake_ref: flake_ref.into(),
        }
    }

    #[test]
    fn allowlisted_tools_from_the_pin_are_auto_allowed() {
        for tool in ALLOWLIST {
            let decision = policy().decide(&request(tool, nix(&format!("{PIN}#{tool}"))));
            assert!(
                matches!(&decision, ToolDecision::AutoAllowed { rule } if rule.contains(tool)),
                "{tool} from the pin is auto-allowed"
            );
        }
    }

    #[test]
    fn anything_else_well_formed_waits_for_a_commander() {
        let unlisted = policy().decide(&request("nmap", nix(&format!("{PIN}#nmap"))));
        assert_eq!(unlisted, ToolDecision::Pending, "nmap is not allowlisted");
        let other_rev = policy().decide(&request(
            "volatility3",
            nix("github:NixOS/nixpkgs/0000000000000000000000000000000000000000#volatility3"),
        ));
        assert_eq!(
            other_rev,
            ToolDecision::Pending,
            "an allowlisted tool from another revision is outside policy"
        );
        let mismatched = policy().decide(&request("yara", nix(&format!("{PIN}#nmap"))));
        assert_eq!(
            mismatched,
            ToolDecision::Pending,
            "the reference must build the tool it names"
        );
    }

    #[test]
    fn malformed_or_unsupported_requests_are_denied() {
        let oci = policy().decide(&request(
            "tshark",
            ToolSource::Oci {
                image: "docker.io/library/wireshark".into(),
                manifest: "sha256:00".into(),
            },
        ));
        assert!(
            matches!(oci, ToolDecision::Denied { .. }),
            "OCI tool sources are denied"
        );
        let option = policy().decide(&request("yara", nix("--impure#yara")));
        assert!(
            matches!(option, ToolDecision::Denied { .. }),
            "a reference that starts with an option is denied"
        );
        let shell = policy().decide(&request("yara", nix(&format!("{PIN}#yara; rm -rf /"))));
        assert!(
            matches!(shell, ToolDecision::Denied { .. }),
            "shell metacharacters are denied"
        );
        let name = policy().decide(&request("../yara", nix(&format!("{PIN}#yara"))));
        assert!(
            matches!(name, ToolDecision::Denied { .. }),
            "a malformed tool name is denied"
        );
    }
}
