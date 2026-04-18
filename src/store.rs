//! Keystore open + key resolution helpers.
//!
//! Lifted from `tumpa-cli/src/store.rs`.

use std::path::{Path, PathBuf};

use wecanencrypt::{KeyInfo, KeyStore, KeyType, SubkeyInfo};

use crate::error::{Error, Result};
use crate::paths;

/// Open the tumpa keystore at the given path or fall back to
/// [`paths::default_keystore_path`].
///
/// Creates the parent directory and database file if they don't exist.
pub fn open_keystore(path: Option<&Path>) -> Result<KeyStore> {
    let db_path: PathBuf = match path {
        Some(p) => p.to_path_buf(),
        None => paths::default_keystore_path()?,
    };

    let preexisting = db_path.exists();
    log::debug!(
        "open_keystore: path={:?} preexisting={} size={:?}",
        db_path,
        preexisting,
        db_path.metadata().ok().map(|m| m.len()),
    );

    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            log::debug!("open_keystore: creating parent dir {:?}", parent);
            std::fs::create_dir_all(parent)?;
        }
    }

    let ks = KeyStore::open(&db_path)
        .map_err(|e| Error::KeyStore(format!("Failed to open {:?}: {e}", db_path)))?;
    log::debug!("open_keystore: opened OK ({:?})", db_path);
    Ok(ks)
}

/// Resolve a signer ID (fingerprint, key ID, or subkey fingerprint) to key
/// data + info.
///
/// Accepts 40-char primary fingerprint, 16-char key ID, or 40-char subkey
/// fingerprint. All may be prefixed with `0x`. The wecanencrypt keystore
/// stores fingerprints and key IDs in uppercase, so the input is normalized.
pub fn resolve_signer(store: &KeyStore, id: &str) -> Result<(Vec<u8>, KeyInfo)> {
    let id = id.strip_prefix("0x").unwrap_or(id);
    let id_upper = id.to_uppercase();

    if id.len() == 40 {
        if let Ok((data, info)) = store.get_key(&id_upper) {
            return Ok((data, info));
        }
    }

    if id.len() == 16 {
        if let Ok(Some(data)) = store.find_by_key_id(&id_upper) {
            let info = wecanencrypt::parse_key_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    if id.len() == 40 {
        if let Ok(Some(data)) = store.find_by_subkey_fingerprint(&id_upper) {
            let info = wecanencrypt::parse_key_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    Err(Error::KeyNotFound(id.to_string()))
}

/// Extract the issuer fingerprint or key ID from a parsed signature config.
///
/// Returns a list of possible identifiers (fingerprints first, then key IDs).
pub fn extract_issuer_ids(sig: &pgp::packet::SignatureConfig) -> Vec<String> {
    let mut ids = Vec::new();
    for fp in sig.issuer_fingerprint() {
        ids.push(hex::encode(fp.as_bytes()));
    }
    for kid in sig.issuer_key_id() {
        ids.push(hex::encode(kid));
    }
    ids
}

/// Look up a key in the keystore by issuer info extracted from a signature.
pub fn resolve_from_issuer_ids(
    store: &KeyStore,
    issuer_ids: &[String],
) -> Result<Option<(Vec<u8>, KeyInfo)>> {
    for id in issuer_ids {
        if let Ok(result) = resolve_signer(store, id) {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn key_is_expired(key_info: &KeyInfo) -> bool {
    key_info
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

pub fn subkey_is_expired(subkey: &SubkeyInfo) -> bool {
    subkey
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

fn has_usable_subkey(key_info: &KeyInfo, key_type: KeyType) -> bool {
    key_info.subkeys.iter().any(|subkey| {
        subkey.key_type == key_type && !subkey.is_revoked && !subkey_is_expired(subkey)
    })
}

pub fn ensure_key_usable_for_signing(key_info: &KeyInfo) -> Result<()> {
    if key_info.is_revoked {
        return Err(Error::unusable(&key_info.fingerprint, "revoked"));
    }
    if key_is_expired(key_info) {
        return Err(Error::unusable(&key_info.fingerprint, "expired"));
    }
    if key_info.can_primary_sign || has_usable_subkey(key_info, KeyType::Signing) {
        return Ok(());
    }
    Err(Error::unusable(
        &key_info.fingerprint,
        "no usable signing-capable key material",
    ))
}

pub fn ensure_key_usable_for_encryption(key_info: &KeyInfo) -> Result<()> {
    if key_info.is_revoked {
        return Err(Error::unusable(&key_info.fingerprint, "revoked"));
    }
    if key_is_expired(key_info) {
        return Err(Error::unusable(&key_info.fingerprint, "expired"));
    }
    if has_usable_subkey(key_info, KeyType::Encryption) {
        return Ok(());
    }
    Err(Error::unusable(
        &key_info.fingerprint,
        "no usable encryption-capable subkey",
    ))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use wecanencrypt::{
        create_key, create_key_simple, parse_key_bytes, revoke_key, CipherSuite, SubkeyFlags,
    };

    use super::{ensure_key_usable_for_encryption, ensure_key_usable_for_signing};

    const TEST_PASSWORD: &str = "test-password";

    #[test]
    fn rejects_revoked_keys_for_signing_and_encryption() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&key.secret_key, TEST_PASSWORD).unwrap();
        let key_info = parse_key_bytes(&revoked, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn rejects_expired_keys_for_signing_and_encryption() {
        let creation_time = Utc::now() - Duration::days(3);
        let primary_expiry = Utc::now() - Duration::days(1);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            Some(primary_expiry),
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn rejects_keys_with_only_expired_subkeys() {
        let creation_time = Utc::now() - Duration::days(3);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            None,
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn accepts_non_revoked_non_expired_keys() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        ensure_key_usable_for_signing(&key_info).unwrap();
        ensure_key_usable_for_encryption(&key_info).unwrap();
    }
}
