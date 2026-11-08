//! Preferences that outlive a session: the last theme chosen with `T`, one name in
//! `$XDG_CONFIG_HOME/cleanroom/theme` (`~/.config/cleanroom/theme` without it).

use std::path::{Path, PathBuf};
use std::{env, fs, io};

use crate::theme::Name;

/// Where the theme is saved, if a config directory can be found.
pub(crate) fn theme_path() -> Option<PathBuf> {
    let config = env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(config.join("cleanroom").join("theme"))
}

/// The theme saved at `path`, if there is a valid one.
pub(crate) fn load_theme(path: &Path) -> Option<Name> {
    let text = fs::read_to_string(path).ok()?;
    Name::parse(text.lines().next().unwrap_or_default())
}

/// Save `name` at `path`, creating its directory.
///
/// # Errors
/// Fails when the directory or the file can't be written.
pub(crate) fn save_theme(path: &Path, name: Name) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", name.label()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_theme_loads_back_and_a_missing_or_bad_file_loads_nothing() {
        let dir = env::temp_dir().join(format!("cleanroom-prefs-{}", std::process::id()));
        let path = dir.join("cleanroom").join("theme");
        assert_eq!(load_theme(&path), None, "nothing saved yet");
        save_theme(&path, Name::Phosphor).expect("save");
        assert_eq!(load_theme(&path), Some(Name::Phosphor));
        fs::write(&path, "plaid\n").expect("overwrite");
        assert_eq!(load_theme(&path), None, "unknown names are ignored");
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
