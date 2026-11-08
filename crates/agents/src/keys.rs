//! Per-role Ed25519 signing keys: `<keys_dir>/<role>.key`, a hex seed with mode 0600.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{generate_key, signing_key_from_hex};
use ed25519_dalek::SigningKey;

/// Load `<dir>/<name>.key`, creating it on first run.
///
/// # Errors
/// Fails if the key file is unreadable, readable by other users, or not a 64-digit hex seed,
/// or if a new key cannot be generated or written.
pub(crate) fn load_or_create(dir: &Path, name: &str) -> Result<SigningKey> {
    let path = dir.join(format!("{name}.key"));
    match fs::read_to_string(&path) {
        Ok(seed) => {
            let mode = fs::metadata(&path)
                .with_context(|| format!("cannot stat {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "{} is readable by other users (mode {:o}); run chmod 600 on it",
                    path.display(),
                    mode & 0o777
                );
            }
            signing_key_from_hex(seed.trim())
                .with_context(|| format!("{} is not a hex Ed25519 seed", path.display()))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => create(dir, &path),
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Generate a key and write its seed with mode 0600.
///
/// # Errors
/// Fails if the directory or file cannot be created or the OS has no randomness.
fn create(dir: &Path, path: &Path) -> Result<SigningKey> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let key = generate_key().context("cannot generate a signing key")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    writeln!(file, "{}", hex::encode(key.to_bytes()))
        .with_context(|| format!("cannot write {}", path.display()))?;
    tracing::info!(path = %path.display(), "created signing key");
    Ok(key)
}
