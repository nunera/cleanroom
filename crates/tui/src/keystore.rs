//! The commander's Ed25519 signing key: a hex seed in a mode-0600 file, created on first run.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::{env, fmt};

use cleanroom_proto::sign::{self, SignError};
use ed25519_dalek::SigningKey;

/// Why the commander key could not be loaded or created.
#[derive(Debug)]
pub(crate) enum KeyError {
    /// Neither `XDG_STATE_HOME` nor `HOME` is set.
    NoStateDir,
    /// Reading, creating or writing the key file failed.
    Io {
        /// The key file or its directory.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The file holds no valid seed, or the OS had no randomness for a new one.
    Key {
        /// The key file.
        path: PathBuf,
        /// What went wrong.
        source: SignError,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoStateDir => {
                f.write_str("cannot locate the commander key: set XDG_STATE_HOME or HOME")
            }
            Self::Io { path, source } => write!(f, "commander key {}: {source}", path.display()),
            Self::Key { path, source } => write!(f, "commander key {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoStateDir => None,
            Self::Io { source, .. } => Some(source),
            Self::Key { source, .. } => Some(source),
        }
    }
}

/// `$XDG_STATE_HOME/cleanroom/keys/commander.key`, with the state home defaulting to
/// `~/.local/state`.
///
/// # Errors
/// Fails when neither `XDG_STATE_HOME` nor `HOME` is set.
pub(crate) fn commander_key_path() -> Result<PathBuf, KeyError> {
    let state_home = match env::var_os("XDG_STATE_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => env::var_os("HOME")
            .filter(|dir| !dir.is_empty())
            .map(|home| Path::new(&home).join(".local").join("state"))
            .ok_or(KeyError::NoStateDir)?,
    };
    Ok(state_home
        .join("cleanroom")
        .join("keys")
        .join("commander.key"))
}

/// Load the key at `path`, creating it (file mode 0600, directory 0700) when it doesn't exist.
///
/// # Errors
/// Fails when the file can't be read or created, or doesn't hold a hex seed.
pub(crate) fn load_or_create(path: &Path) -> Result<SigningKey, KeyError> {
    match fs::read_to_string(path) {
        Ok(text) => parse(path, &text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(path),
        Err(source) => Err(io_error(path, source)),
    }
}

/// Generate a key and write its seed to a new file at `path`.
///
/// # Errors
/// Fails when the directory or file can't be created or written, or the OS has no randomness.
fn create(path: &Path) -> Result<SigningKey, KeyError> {
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|source| io_error(dir, source))?;
    }
    let key = sign::generate_key().map_err(|source| KeyError::Key {
        path: path.to_owned(),
        source,
    })?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        // Another console created it between our read and this open: use that one.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let text = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
            return parse(path, &text);
        }
        Err(source) => return Err(io_error(path, source)),
    };
    writeln!(file, "{}", hex::encode(key.to_bytes()))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))?;
    Ok(key)
}

/// Parse a hex seed read from `path`.
///
/// # Errors
/// Fails when `text` is not 64 hex digits.
fn parse(path: &Path, text: &str) -> Result<SigningKey, KeyError> {
    sign::signing_key_from_hex(text.trim()).map_err(|source| KeyError::Key {
        path: path.to_owned(),
        source,
    })
}

/// Attach `path` to an I/O error.
fn io_error(path: &Path, source: io::Error) -> KeyError {
    KeyError::Io {
        path: path.to_owned(),
        source,
    }
}
