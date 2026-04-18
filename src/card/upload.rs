//! Upload keys to a smartcard.
//!
//! Ported from `tumpa/src-tauri/src/commands/card.rs::upload_key_to_card`.
//! Card-linking is now persisted in the keystore's `card_keys` table via
//! [`super::link::auto_link_after_upload`].

use wecanencrypt::card::{
    get_card_details, reset_card, upload_key_to_card as we_upload_key_to_card,
    upload_primary_key_to_card, upload_subkey_by_fingerprint, CardKeySlot,
};
use wecanencrypt::{parse_key_bytes, update_password, KeyStore, KeyType};

use super::{link, require_card_connected};
use crate::error::{Error, Result};

/// Default admin PIN on a freshly reset OpenPGP card.
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

/// Bitmask flags for [`upload`].
pub mod flags {
    /// Upload the encryption subkey.
    pub const ENCRYPTION: u8 = 1;
    /// Upload the primary key into the signing slot.
    pub const PRIMARY_TO_SIGNING: u8 = 2;
    /// Upload the authentication subkey.
    pub const AUTHENTICATION: u8 = 4;
    /// Upload the signing subkey into the signing slot. Mutually exclusive
    /// with [`PRIMARY_TO_SIGNING`].
    pub const SIGNING_SUBKEY: u8 = 8;
}

/// Upload keys to the connected OpenPGP card.
///
/// Performs a factory reset first, then uploads the requested slots, then
/// records `(key, card, slot)` associations in the keystore's `card_keys`
/// table via [`link::auto_link_after_upload`].
///
/// `which` is a bitmask from [`flags`].
pub fn upload(
    store: &KeyStore,
    key_fingerprint: &str,
    password: &str,
    which: u8,
) -> Result<()> {
    require_card_connected()?;

    if which & flags::PRIMARY_TO_SIGNING != 0 && which & flags::SIGNING_SUBKEY != 0 {
        return Err(Error::InvalidInput(
            "cannot upload both primary key and signing subkey to the signing slot".into(),
        ));
    }

    let (cert_data, _) = store
        .get_key(key_fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{key_fingerprint}: {e}")))?;

    let cert_info = parse_key_bytes(&cert_data, true)?;

    // Verify the passphrase up front — no-op password "change" proves we
    // can unlock the secret key material before we touch the card.
    update_password(&cert_data, password, password)
        .map_err(|_| Error::InvalidInput("incorrect key password".into()))?;

    reset_card(None).map_err(|e| Error::Card(format!("reset: {e}")))?;

    if which & flags::PRIMARY_TO_SIGNING != 0 {
        upload_primary_key_to_card(
            &cert_data,
            password.as_bytes(),
            CardKeySlot::Signing,
            DEFAULT_ADMIN_PIN,
        )
        .map_err(|e| Error::Card(format!("upload primary→signing: {e}")))?;
    }

    if which & flags::SIGNING_SUBKEY != 0 {
        let sign_sk = cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Signing))
            .ok_or_else(|| Error::InvalidInput("no signing subkey found".into()))?;

        upload_subkey_by_fingerprint(
            &cert_data,
            password.as_bytes(),
            &sign_sk.fingerprint,
            CardKeySlot::Signing,
            DEFAULT_ADMIN_PIN,
        )
        .map_err(|e| Error::Card(format!("upload signing subkey: {e}")))?;
    }

    if which & flags::ENCRYPTION != 0 {
        let _ = cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Encryption))
            .ok_or_else(|| Error::InvalidInput("no encryption subkey found".into()))?;

        we_upload_key_to_card(
            &cert_data,
            password.as_bytes(),
            CardKeySlot::Decryption,
            DEFAULT_ADMIN_PIN,
        )
        .map_err(|e| Error::Card(format!("upload encryption: {e}")))?;
    }

    if which & flags::AUTHENTICATION != 0 {
        let auth = cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Authentication))
            .ok_or_else(|| Error::InvalidInput("no authentication subkey found".into()))?;

        upload_subkey_by_fingerprint(
            &cert_data,
            password.as_bytes(),
            &auth.fingerprint,
            CardKeySlot::Authentication,
            DEFAULT_ADMIN_PIN,
        )
        .map_err(|e| Error::Card(format!("upload authentication: {e}")))?;
    }

    // Best-effort auto-link after upload.
    if let Ok(info) = get_card_details(None) {
        let _ = link::auto_link_after_upload(store, &info, key_fingerprint);
    }

    Ok(())
}
