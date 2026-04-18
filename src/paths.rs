//! Filesystem paths used by tumpa apps.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Resolve the tumpa config directory.
///
/// Returns `$TUMPA_DIR` if set, otherwise `~/.tumpa`.
pub fn tumpa_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("TUMPA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| Error::InvalidInput("Could not determine home directory".into()))?;
    Ok(home.join(".tumpa"))
}

/// Resolve the tumpa keystore database path.
///
/// Returns `$TUMPA_KEYSTORE` if set, otherwise `<tumpa_dir>/keys.db`.
pub fn default_keystore_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("TUMPA_KEYSTORE") {
        return Ok(PathBuf::from(p));
    }
    Ok(tumpa_dir()?.join("keys.db"))
}
