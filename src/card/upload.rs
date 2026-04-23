//! Upload keys to a smartcard.
//!
//! Ported from `tumpa/src-tauri/src/commands/card.rs::upload_key_to_card`.
//! Card-linking is now persisted in the keystore's `card_keys` table via
//! [`super::link::auto_link_after_upload`].

use wecanencrypt::card::{
    get_card_details, reset_card, upload_key_to_card as we_upload_key_to_card,
    upload_primary_key_to_card, upload_subkey_by_fingerprint, CardKeySlot,
};
use wecanencrypt::{parse_key_bytes, update_password, KeyAlgorithm, KeyInfo, KeyStore, KeyType};

use super::{link, require_safe_implicit_card_target};
use crate::error::{Error, Result};
use crate::Passphrase;

/// Default admin PIN on a freshly reset OpenPGP card. This is the
/// factory constant — not a user secret — so it is a plain byte slice.
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

/// OpenPGP card manufacturer code for Nitrokey GmbH (assigned in the
/// card's Application ID).
const NITROKEY_MANUFACTURER_CODE: &str = "000F";

/// Returns true if `alg` is known to be unsupported by Nitrokey firmware.
///
/// Nitrokey only accepts `Cv25519Modern` (Ed25519 + X25519) among the
/// Curve25519/448 cipher suites. `Cv25519` (legacy EdDSA + ECDH/Curve25519)
/// and `Cv448Modern` (Ed448 + X448) are rejected here; RSA and NIST ECC
/// fall through.
fn is_nitrokey_unsupported(alg: KeyAlgorithm) -> bool {
    matches!(
        alg,
        KeyAlgorithm::EdDsaLegacy
            | KeyAlgorithm::EcdhCurve25519
            | KeyAlgorithm::Ed448
            | KeyAlgorithm::X448
    )
}

/// Pure classifier used by [`check_card_algorithm_compat`]: given the
/// slot selection and cert metadata, return the first algorithm that
/// would be rejected on a Nitrokey, or `None` if the upload is allowed.
fn nitrokey_upload_violation(cert_info: &KeyInfo, which: u8) -> Option<KeyAlgorithm> {
    if which & flags::PRIMARY_TO_SIGNING != 0
        && is_nitrokey_unsupported(cert_info.primary_algorithm_detail)
    {
        return Some(cert_info.primary_algorithm_detail);
    }
    let check_subkey = |kt: KeyType| -> Option<KeyAlgorithm> {
        cert_info
            .subkeys
            .iter()
            .find(|sk| sk.key_type == kt)
            .map(|sk| sk.algorithm_detail)
            .filter(|alg| is_nitrokey_unsupported(*alg))
    };
    if which & flags::SIGNING_SUBKEY != 0 {
        if let Some(a) = check_subkey(KeyType::Signing) {
            return Some(a);
        }
    }
    if which & flags::ENCRYPTION != 0 {
        if let Some(a) = check_subkey(KeyType::Encryption) {
            return Some(a);
        }
    }
    if which & flags::AUTHENTICATION != 0 {
        if let Some(a) = check_subkey(KeyType::Authentication) {
            return Some(a);
        }
    }
    None
}

/// Preflight: reject key algorithms that the target card's firmware is
/// known not to accept. This runs before `reset_card` so the user's card
/// is never wiped for an upload that would fail mid-flow.
fn check_card_algorithm_compat(
    ident: Option<&str>,
    cert_info: &KeyInfo,
    which: u8,
) -> Result<()> {
    let Ok(card_info) = get_card_details(ident) else {
        return Ok(());
    };
    let is_nitrokey = card_info
        .manufacturer
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case(NITROKEY_MANUFACTURER_CODE))
        .unwrap_or(false);
    if !is_nitrokey {
        return Ok(());
    }
    let card_label = card_info
        .manufacturer_name
        .clone()
        .unwrap_or_else(|| "Nitrokey".to_string());

    if let Some(alg) = nitrokey_upload_violation(cert_info, which) {
        return Err(Error::CardUnsupportedAlgorithm {
            card: card_label,
            algorithm: alg.name().to_string(),
        });
    }
    Ok(())
}

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
///
/// When `ident` is `None` and multiple cards are connected, this function
/// refuses to run; pass `ident` to disambiguate. The ident is threaded to
/// wecanencrypt so `reset_card` and every slot upload bind to that specific
/// card.
pub fn upload(
    store: &KeyStore,
    key_fingerprint: &str,
    password: &Passphrase,
    which: u8,
    ident: Option<&str>,
) -> Result<()> {
    require_safe_implicit_card_target(ident)?;

    if which == 0 {
        return Err(Error::InvalidInput(
            "must select at least one slot to upload".into(),
        ));
    }

    if which & flags::PRIMARY_TO_SIGNING != 0 && which & flags::SIGNING_SUBKEY != 0 {
        return Err(Error::InvalidInput(
            "cannot upload both primary key and signing subkey to the signing slot".into(),
        ));
    }

    let (cert_data, _) = store
        .get_key(key_fingerprint)
        .map_err(|e| Error::KeyNotFound(format!("{key_fingerprint}: {e}")))?;

    let cert_info = parse_key_bytes(&cert_data, true)?;

    if which & flags::SIGNING_SUBKEY != 0 {
        cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Signing))
            .ok_or_else(|| Error::InvalidInput("no signing subkey found".into()))?;
    }

    if which & flags::ENCRYPTION != 0 {
        cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Encryption))
            .ok_or_else(|| Error::InvalidInput("no encryption subkey found".into()))?;
    }

    if which & flags::AUTHENTICATION != 0 {
        cert_info
            .subkeys
            .iter()
            .find(|sk| matches!(sk.key_type, KeyType::Authentication))
            .ok_or_else(|| Error::InvalidInput("no authentication subkey found".into()))?;
    }

    // Verify the passphrase up front — no-op password "change" proves we
    // can unlock the secret key material before we touch the card.
    update_password(&cert_data, password.as_str(), password.as_str())
        .map_err(|_| Error::InvalidInput("incorrect key password".into()))?;

    // Reject unsupported algorithms before the destructive reset, so we
    // never wipe a card for a key its firmware can't hold.
    check_card_algorithm_compat(ident, &cert_info, which)?;

    reset_card(ident).map_err(|e| Error::Card(format!("reset: {e}")))?;

    if which & flags::PRIMARY_TO_SIGNING != 0 {
        upload_primary_key_to_card(
            &cert_data,
            password.as_bytes(),
            CardKeySlot::Signing,
            DEFAULT_ADMIN_PIN,
            ident,
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
            ident,
        )
        .map_err(|e| Error::Card(format!("upload signing subkey: {e}")))?;
    }

    if which & flags::ENCRYPTION != 0 {
        we_upload_key_to_card(
            &cert_data,
            password.as_bytes(),
            CardKeySlot::Decryption,
            DEFAULT_ADMIN_PIN,
            ident,
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
            ident,
        )
        .map_err(|e| Error::Card(format!("upload authentication: {e}")))?;
    }

    // Best-effort auto-link after upload.
    if let Ok(info) = get_card_details(ident) {
        let _ = link::auto_link_after_upload(store, &info, key_fingerprint);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};

    fn info_for(suite: CipherSuite) -> KeyInfo {
        let key = create_key(
            "pw",
            &["Alice <a@e.com>"],
            suite,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        parse_key_bytes(&key.secret_key, true).unwrap()
    }

    #[test]
    fn nitrokey_allows_cv25519_modern() {
        let info = info_for(CipherSuite::Cv25519Modern);
        let which = flags::PRIMARY_TO_SIGNING | flags::ENCRYPTION | flags::AUTHENTICATION;
        assert!(nitrokey_upload_violation(&info, which).is_none());
    }

    #[test]
    fn nitrokey_allows_rsa() {
        let info = info_for(CipherSuite::Rsa2k);
        let which = flags::PRIMARY_TO_SIGNING | flags::ENCRYPTION | flags::AUTHENTICATION;
        assert!(nitrokey_upload_violation(&info, which).is_none());
    }

    #[test]
    fn nitrokey_rejects_cv25519_legacy_primary() {
        let info = info_for(CipherSuite::Cv25519);
        assert_eq!(
            nitrokey_upload_violation(&info, flags::PRIMARY_TO_SIGNING),
            Some(KeyAlgorithm::EdDsaLegacy)
        );
    }

    #[test]
    fn nitrokey_rejects_cv25519_legacy_encryption_subkey() {
        let info = info_for(CipherSuite::Cv25519);
        assert_eq!(
            nitrokey_upload_violation(&info, flags::ENCRYPTION),
            Some(KeyAlgorithm::EcdhCurve25519)
        );
    }

    #[test]
    fn nitrokey_rejects_cv448_modern() {
        let info = info_for(CipherSuite::Cv448Modern);
        // Ed448 surfaces first (primary), then X448 on encryption-only.
        assert_eq!(
            nitrokey_upload_violation(&info, flags::PRIMARY_TO_SIGNING),
            Some(KeyAlgorithm::Ed448)
        );
        assert_eq!(
            nitrokey_upload_violation(&info, flags::ENCRYPTION),
            Some(KeyAlgorithm::X448)
        );
    }
}
