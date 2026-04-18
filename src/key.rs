//! High-level key lifecycle: generate, import, export, add/revoke UID,
//! change password, revoke, update expiry.
//!
//! These wrappers hide the split between `wecanencrypt`'s pure key functions
//! (that take `&[u8]` cert data) and the [`KeyStore`] update step, so
//! callers don't have to juggle the two.
//!
//! Ported from `tumpa/src-tauri/src/commands/keystore.rs` (without the
//! `#[tauri::command]` / `State<_>` wiring).

use chrono::{DateTime, Utc};
use wecanencrypt::{
    add_uid as we_add_uid, create_key, parse_key_bytes, revoke_key as we_revoke_key,
    revoke_uid as we_revoke_uid, update_password, update_primary_expiry, update_subkeys_expiry,
    CipherSuite, GeneratedKey, KeyInfo, KeyStore, KeyType, SubkeyFlags,
};

use crate::error::{Error, Result};

/// Parameters for generating a new key.
#[derive(Debug, Clone)]
pub struct GenerateKeyParams {
    /// UIDs (each should be `"Name <email>"` format).
    pub uids: Vec<String>,
    /// Cipher suite to use.
    pub cipher_suite: CipherSuite,
    /// Primary and subkey expiry (`None` = never).
    pub expiry: Option<DateTime<Utc>>,
    /// Which subkeys to generate.
    pub subkey_flags: SubkeyFlags,
    /// Whether the primary key can sign.
    pub can_primary_sign: bool,
}

impl Default for GenerateKeyParams {
    fn default() -> Self {
        Self {
            uids: Vec::new(),
            cipher_suite: CipherSuite::Cv25519,
            expiry: None,
            subkey_flags: SubkeyFlags::all(),
            can_primary_sign: true,
        }
    }
}

/// Generate a new keypair. The secret key bytes are wrapped in
/// [`zeroize::Zeroizing`] by wecanencrypt; the caller is responsible for
/// importing them into a keystore (or using them directly) before they go
/// out of scope.
pub fn generate(params: GenerateKeyParams, password: &str) -> Result<GeneratedKey> {
    let uid_refs: Vec<&str> = params.uids.iter().map(|s| s.as_str()).collect();
    let result = create_key(
        password,
        &uid_refs,
        params.cipher_suite,
        None,
        params.expiry,
        params.expiry,
        params.subkey_flags,
        params.can_primary_sign,
        true,
    )?;
    Ok(result)
}

/// Generate a key and import it into the keystore in one shot.
/// Returns the primary fingerprint and up-to-date [`KeyInfo`].
pub fn generate_and_import(
    store: &KeyStore,
    params: GenerateKeyParams,
    password: &str,
) -> Result<KeyInfo> {
    let generated = generate(params, password)?;
    let fp = store
        .import_key(&generated.secret_key)
        .map_err(|e| Error::KeyStore(format!("import after generate: {e}")))?;
    store
        .get_key_info(&fp)
        .map_err(|e| Error::KeyStore(format!("read info after generate: {e}")))
}

/// Import a secret key from raw bytes. Rejects public-only keys.
pub fn import_secret(store: &KeyStore, data: &[u8]) -> Result<KeyInfo> {
    let info = parse_key_bytes(data, true)?;
    if !info.is_secret {
        return Err(Error::InvalidInput(
            "not a secret key (import_secret rejects public-only input)".into(),
        ));
    }
    let fp = store
        .import_key(data)
        .map_err(|e| Error::KeyStore(format!("import_key: {e}")))?;
    store
        .get_key_info(&fp)
        .map_err(|e| Error::KeyStore(format!("read info after import: {e}")))
}

/// Import either a secret or public key.
pub fn import_any(store: &KeyStore, data: &[u8]) -> Result<KeyInfo> {
    let _info = parse_key_bytes(data, true)?;
    let fp = store
        .import_key(data)
        .map_err(|e| Error::KeyStore(format!("import_key: {e}")))?;
    store
        .get_key_info(&fp)
        .map_err(|e| Error::KeyStore(format!("read info after import: {e}")))
}

/// Delete a key from the store.
pub fn delete(store: &KeyStore, fingerprint: &str) -> Result<()> {
    store
        .delete_key(fingerprint)
        .map_err(|e| Error::KeyStore(format!("delete_key: {e}")))?;
    Ok(())
}

/// Export the ASCII-armored public key for a fingerprint.
pub fn export_public_armored(store: &KeyStore, fingerprint: &str) -> Result<String> {
    store
        .export_key_armored(fingerprint)
        .map_err(|e| Error::KeyStore(format!("export_key_armored: {e}")))
}

/// Add a new UID (`"Name <email>"`) to an existing key.
pub fn add_uid(
    store: &KeyStore,
    fingerprint: &str,
    uid: &str,
    password: &str,
) -> Result<KeyInfo> {
    let (cert_data, _) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;
    let updated = we_add_uid(&cert_data, uid, password)?;
    store
        .update_key(fingerprint, &updated)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Revoke a UID on an existing key.
pub fn revoke_uid(
    store: &KeyStore,
    fingerprint: &str,
    uid: &str,
    password: &str,
) -> Result<KeyInfo> {
    let (cert_data, _) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;
    let updated = we_revoke_uid(&cert_data, uid, password)?;
    store
        .update_key(fingerprint, &updated)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Revoke the primary key.
pub fn revoke(store: &KeyStore, fingerprint: &str, password: &str) -> Result<KeyInfo> {
    let (cert_data, _) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;
    let revoked = we_revoke_key(&cert_data, password)?;
    store
        .update_key(fingerprint, &revoked)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Change the passphrase protecting the secret key material.
pub fn change_password(
    store: &KeyStore,
    fingerprint: &str,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    let (cert_data, _) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;
    let updated = update_password(&cert_data, old_password, new_password)?;
    store
        .update_key(fingerprint, &updated)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    Ok(())
}

/// Update the expiry of the primary key and every non-certification subkey.
pub fn update_expiry(
    store: &KeyStore,
    fingerprint: &str,
    expiry: DateTime<Utc>,
    password: &str,
) -> Result<KeyInfo> {
    let (cert_data, info) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;

    let updated = update_primary_expiry(&cert_data, expiry, password)?;

    let subkey_fps: Vec<String> = info
        .subkeys
        .iter()
        .filter(|sk| sk.key_type != KeyType::Certification)
        .map(|sk| sk.fingerprint.clone())
        .collect();

    let final_cert = if subkey_fps.is_empty() {
        updated
    } else {
        let fp_refs: Vec<&str> = subkey_fps.iter().map(|s| s.as_str()).collect();
        update_subkeys_expiry(&updated, &fp_refs, expiry, password)?
    };

    store
        .update_key(fingerprint, &final_cert)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Update the expiry of only the specified subkeys (primary is untouched).
pub fn update_subkey_expiry(
    store: &KeyStore,
    fingerprint: &str,
    subkey_fingerprints: &[&str],
    expiry: DateTime<Utc>,
    password: &str,
) -> Result<KeyInfo> {
    let (cert_data, _) = store
        .get_key(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;

    let updated = update_subkeys_expiry(&cert_data, subkey_fingerprints, expiry, password)?;

    store
        .update_key(fingerprint, &updated)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;
    store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Availability of signing / encryption / authentication capability.
#[derive(Debug, Clone, Copy)]
pub struct SubkeyAvailability {
    pub primary_can_sign: bool,
    pub signing_subkey: bool,
    pub encryption: bool,
    pub authentication: bool,
}

/// Report which capabilities this key currently has from non-revoked,
/// non-expired material.
pub fn available_subkeys(store: &KeyStore, fingerprint: &str) -> Result<SubkeyAvailability> {
    let info = store
        .get_key_info(fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{fingerprint}: {e}")))?;

    let now = Utc::now();
    let mut avail = SubkeyAvailability {
        primary_can_sign: info.can_primary_sign,
        signing_subkey: false,
        encryption: false,
        authentication: false,
    };
    for sk in &info.subkeys {
        if sk.is_revoked {
            continue;
        }
        if let Some(exp) = sk.expiration_time {
            if exp < now {
                continue;
            }
        }
        match sk.key_type {
            KeyType::Encryption => avail.encryption = true,
            KeyType::Signing => avail.signing_subkey = true,
            KeyType::Authentication => avail.authentication = true,
            _ => {}
        }
    }
    Ok(avail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::KeyStore;

    fn in_memory_store() -> KeyStore {
        KeyStore::open_in_memory().unwrap()
    }

    #[test]
    fn generate_import_delete_roundtrip() {
        let store = in_memory_store();
        let params = GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        };
        let info = generate_and_import(&store, params, "pw").unwrap();
        assert!(info.is_secret);
        assert_eq!(info.user_ids[0].value, "Alice <alice@example.com>");

        delete(&store, &info.fingerprint).unwrap();
        assert!(store.get_key_info(&info.fingerprint).is_err());
    }

    #[test]
    fn add_and_revoke_uid() {
        let store = in_memory_store();
        let params = GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        };
        let info = generate_and_import(&store, params, "pw").unwrap();
        let fp = info.fingerprint.clone();

        let info = add_uid(&store, &fp, "Alice 2 <alice2@example.com>", "pw").unwrap();
        assert_eq!(info.user_ids.len(), 2);

        let info = revoke_uid(&store, &fp, "Alice 2 <alice2@example.com>", "pw").unwrap();
        let revoked = info
            .user_ids
            .iter()
            .find(|u| u.value == "Alice 2 <alice2@example.com>")
            .unwrap();
        assert!(revoked.revoked);
    }

    #[test]
    fn export_public_armored_works() {
        let store = in_memory_store();
        let params = GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        };
        let info = generate_and_import(&store, params, "pw").unwrap();

        let armored = export_public_armored(&store, &info.fingerprint).unwrap();
        assert!(armored.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[test]
    fn change_password_works() {
        let store = in_memory_store();
        let params = GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        };
        let info = generate_and_import(&store, params, "old").unwrap();

        change_password(&store, &info.fingerprint, "old", "new").unwrap();
        // Confirm new password now works by issuing another operation
        add_uid(&store, &info.fingerprint, "Alice 2 <a2@example.com>", "new").unwrap();
    }
}
