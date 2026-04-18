//! Update key/subkey expiry using the card (PIN, not passphrase).
//!
//! Ported from `tumpa/src-tauri/src/commands/card.rs`.

use chrono::{DateTime, Utc};
use wecanencrypt::card::{update_primary_expiry_on_card, update_subkeys_expiry_on_card};
use wecanencrypt::{KeyInfo, KeyStore, KeyType};

use super::require_card_connected;
use crate::error::{Error, Result};
use crate::Pin;

fn expiry_seconds_from_now(expiry: DateTime<Utc>) -> Result<u64> {
    let seconds = (expiry - Utc::now()).num_seconds();
    if seconds <= 0 {
        return Err(Error::InvalidInput("expiry must be in the future".into()));
    }
    Ok(seconds as u64)
}

/// Update the primary key and every non-certification subkey expiry, using
/// the card's signing/authentication key as the signer (PIN-gated).
pub fn update_key_expiry_on_card(
    store: &KeyStore,
    key_fingerprint: &str,
    expiry: DateTime<Utc>,
    pin: &Pin,
) -> Result<KeyInfo> {
    require_card_connected()?;
    let seconds = expiry_seconds_from_now(expiry)?;

    let (_cert_data, info) = store
        .get_key(key_fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{key_fingerprint}: {e}")))?;

    let armored = store
        .export_key_armored(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("export_key_armored: {e}")))?;

    let updated = update_primary_expiry_on_card(armored.as_bytes(), seconds, pin.as_slice())
        .map_err(|e| Error::Card(format!("update_primary_expiry_on_card: {e}")))?;

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
        update_subkeys_expiry_on_card(&updated, &fp_refs, seconds, pin.as_slice())
            .map_err(|e| Error::Card(format!("update_subkeys_expiry_on_card: {e}")))?
    };

    store
        .update_key(key_fingerprint, &final_cert)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;

    store
        .get_key_info(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}

/// Update only the specified subkeys' expiry on the card.
pub fn update_selected_subkeys_expiry_on_card(
    store: &KeyStore,
    key_fingerprint: &str,
    subkey_fingerprints: &[&str],
    expiry: DateTime<Utc>,
    pin: &Pin,
) -> Result<KeyInfo> {
    require_card_connected()?;
    let seconds = expiry_seconds_from_now(expiry)?;

    let armored = store
        .export_key_armored(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("export_key_armored: {e}")))?;

    let updated = update_subkeys_expiry_on_card(
        armored.as_bytes(),
        subkey_fingerprints,
        seconds,
        pin.as_slice(),
    )
    .map_err(|e| Error::Card(format!("update_subkeys_expiry_on_card: {e}")))?;

    store
        .update_key(key_fingerprint, &updated)
        .map_err(|e| Error::KeyStore(format!("update_key: {e}")))?;

    store
        .get_key_info(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("read info: {e}")))
}
