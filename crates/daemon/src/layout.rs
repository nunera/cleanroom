//! Where cleanroomd keeps its state, where it finds the repository's scenario and root locks,
//! and where its socket lives.
//!
//! State (default `$XDG_STATE_HOME/cleanroom`): `store/oci` (OCI layout),
//! `store/containers-policy.json` (skopeo's trust policy), `store/staging/<root>` (copies
//! admission verifies), `store/roots/<root>/rootfs` (unpacked), `keys/` (daemon key, enrolled
//! members), `run/acme-fs/{share,drop,logs}` (live victim), `run/scratch/<role>`, `run/bin`
//! (binaries placed into strata) and `receipts.ndjson`.

use std::env;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cleanroom_proto::Role;

use crate::strata;

/// Every path the daemon uses.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// The Unix socket.
    pub(crate) socket: PathBuf,
    /// Repository root: `scenario/`, `roots/` and `flake.lock`.
    pub(crate) repo: PathBuf,
    /// State root.
    pub(crate) state: PathBuf,
}

impl Layout {
    /// Resolve the socket, state and repository from flags and the environment, and create the
    /// state directory (mode 0700).
    ///
    /// # Errors
    /// Fails if a default needs an unset variable, or a directory cannot be created or resolved.
    pub(crate) fn resolve(
        socket: Option<PathBuf>,
        state: Option<PathBuf>,
        repo: Option<PathBuf>,
    ) -> Result<Self> {
        let socket = match socket {
            Some(path) => std::path::absolute(&path)
                .with_context(|| format!("cannot resolve {}", path.display()))?,
            None => default_socket()?,
        };
        let state = match state {
            Some(path) => path,
            None => default_state()?,
        };
        private_dir(&state)?;
        let state = fs::canonicalize(&state)
            .with_context(|| format!("cannot resolve {}", state.display()))?;
        let repo = match repo {
            Some(path) => path,
            None => find_repo()?,
        };
        let repo = fs::canonicalize(&repo)
            .with_context(|| format!("cannot resolve {}", repo.display()))?;
        Ok(Self {
            socket,
            repo,
            state,
        })
    }

    /// OCI image layout that skopeo fills.
    pub(crate) fn oci(&self) -> PathBuf {
        self.state.join("store/oci")
    }

    /// The containers trust policy cleanroomd hands skopeo, so fetching never depends on the
    /// host's `policy.json`.
    pub(crate) fn containers_policy(&self) -> PathBuf {
        self.state.join("store/containers-policy.json")
    }

    /// Staged copies that admission verifies and `tamper` corrupts.
    pub(crate) fn staging(&self) -> PathBuf {
        self.state.join("store/staging")
    }

    /// Unpacked roots: `<this>/<root>/rootfs`.
    pub(crate) fn roots(&self) -> PathBuf {
        self.state.join("store/roots")
    }

    /// Signing keys and enrolled members.
    pub(crate) fn keys(&self) -> PathBuf {
        self.state.join("keys")
    }

    /// The victim's live file share.
    pub(crate) fn share(&self) -> PathBuf {
        self.state.join("run/acme-fs/share")
    }

    /// The victim's drop box (where the ransomware stages copies).
    pub(crate) fn dropbox(&self) -> PathBuf {
        self.state.join("run/acme-fs/drop")
    }

    /// The victim's logs.
    pub(crate) fn logs(&self) -> PathBuf {
        self.state.join("run/acme-fs/logs")
    }

    /// Scratch directories, one per role.
    pub(crate) fn scratch_root(&self) -> PathBuf {
        self.state.join("run/scratch")
    }

    /// `role`'s scratch directory.
    pub(crate) fn scratch(&self, role: Role) -> PathBuf {
        self.scratch_root().join(strata::stratum_of(role))
    }

    /// Binaries the daemon places into strata.
    pub(crate) fn bin(&self) -> PathBuf {
        self.state.join("run/bin")
    }

    /// The receipt log.
    pub(crate) fn receipts(&self) -> PathBuf {
        self.state.join("receipts.ndjson")
    }

    /// `scenario/assets.json`.
    pub(crate) fn assets(&self) -> PathBuf {
        self.repo.join("scenario/assets.json")
    }

    /// Seed files for the victim share.
    pub(crate) fn seed(&self) -> PathBuf {
        self.repo.join("scenario/acme-fs")
    }

    /// YARA rules, mounted read-only at `/rules`: the repository's rules, copied in at every
    /// seeding, plus the agent rules cleanroomd admitted during the incident.
    pub(crate) fn rules(&self) -> PathBuf {
        self.state.join("run/rules")
    }

    /// The repository's own YARA rules.
    pub(crate) fn rules_seed(&self) -> PathBuf {
        self.repo.join("scenario/rules")
    }

    /// Where a submitted rule waits while cleanroomd checks it.
    pub(crate) fn rule_check(&self) -> PathBuf {
        self.state.join("run/rule-check")
    }

    /// Root lock files.
    pub(crate) fn locks(&self) -> PathBuf {
        self.repo.join("roots")
    }
}

/// `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`.
///
/// # Errors
/// Fails if `XDG_RUNTIME_DIR` is unset.
pub(crate) fn default_socket() -> Result<PathBuf> {
    let runtime =
        env_dir("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR is not set; pass --socket")?;
    Ok(runtime.join("cleanroom/cleanroomd.sock"))
}

/// `$XDG_STATE_HOME/cleanroom`, else `$HOME/.local/state/cleanroom`.
///
/// # Errors
/// Fails if neither variable is set.
fn default_state() -> Result<PathBuf> {
    if let Some(state) = env_dir("XDG_STATE_HOME") {
        return Ok(state.join("cleanroom"));
    }
    let home = env_dir("HOME").context("neither XDG_STATE_HOME nor HOME is set; pass --state")?;
    Ok(home.join(".local/state/cleanroom"))
}

/// A non-empty environment variable as a path.
fn env_dir(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The nearest ancestor of the running binary that holds `scenario/` and `roots/`, else the
/// current directory.
///
/// # Errors
/// Fails if neither the binary's path nor the current directory can be read.
fn find_repo() -> Result<PathBuf> {
    let exe = env::current_exe().context("cannot locate the cleanroomd binary")?;
    if let Some(repo) = exe
        .ancestors()
        .find(|dir| dir.join("scenario").is_dir() && dir.join("roots").is_dir())
    {
        return Ok(repo.to_path_buf());
    }
    env::current_dir().context("cannot read the current directory")
}

/// Create `path` and its parents; new directories get mode 0700.
///
/// # Errors
/// Fails if the directory cannot be created.
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))
}
