//! Encryption.

use wecanencrypt::KeyStore;

use crate::error::{Error, Result};
use crate::store;

/// Encrypt `plaintext` to one or more recipients, resolving each via the
/// keystore. Recipient IDs may be fingerprints, key IDs, subkey
/// fingerprints, or exact email addresses (the same IDs accepted by
/// [`store::resolve_recipient`]).
///
/// Every recipient is validated with [`store::ensure_key_usable_for_encryption`]
/// before encryption.
pub fn encrypt_to_recipients(
    store: &KeyStore,
    recipients: &[&str],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let mut key_data_list: Vec<Vec<u8>> = Vec::new();
    for id in recipients {
        let (data, info) = store::resolve_recipient(store, id)?;
        store::ensure_key_usable_for_encryption(&info)?;
        key_data_list.push(data);
    }
    let key_refs: Vec<&[u8]> = key_data_list.iter().map(|d| d.as_slice()).collect();

    wecanencrypt::encrypt_bytes_to_multiple(&key_refs, plaintext, armor)
        .map_err(|e| Error::Encrypt(format!("encrypt_bytes_to_multiple: {e}")))
}

/// Sign `plaintext` with a software signer key and encrypt to one or more
/// recipients in a single OpenPGP message (sign-then-encrypt).
///
/// `signer_key_data` is the signer's secret key bytes (already resolved
/// from the keystore by the caller); `passphrase` unlocks it. Recipients
/// are resolved through [`store::resolve_recipient`] and validated with
/// [`store::ensure_key_usable_for_encryption`] before encryption.
pub fn sign_and_encrypt_to_recipients(
    store: &KeyStore,
    signer_key_data: &[u8],
    passphrase: &crate::Passphrase,
    recipients: &[&str],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let mut key_data_list: Vec<Vec<u8>> = Vec::new();
    for id in recipients {
        let (data, info) = store::resolve_recipient(store, id)?;
        store::ensure_key_usable_for_encryption(&info)?;
        key_data_list.push(data);
    }
    let key_refs: Vec<&[u8]> = key_data_list.iter().map(|d| d.as_slice()).collect();

    wecanencrypt::sign_and_encrypt_to_multiple(
        signer_key_data,
        passphrase.as_str(),
        &key_refs,
        plaintext,
        armor,
    )
    .map_err(|e| Error::Encrypt(format!("sign_and_encrypt_to_multiple: {e}")))
}

#[cfg(feature = "card")]
mod card_encryption {
    use super::*;
    use crate::Pin;
    use wecanencrypt::card::{find_cards_for_key, CardKeyMatch, KeySlot};

    /// Find a connected card whose signing slot matches `signer_public_key`.
    /// Mirrors [`crate::sign::find_signing_card`] — picks the first card with
    /// a signing-capable slot bound to this key.
    pub fn find_signing_card_for_encrypt(signer_public_key: &[u8]) -> Result<Option<CardKeyMatch>> {
        let matches =
            find_cards_for_key(signer_public_key).map_err(|e| Error::Card(e.to_string()))?;
        for m in matches {
            if m.matching_slots
                .iter()
                .any(|s| matches!(s.slot, KeySlot::Signature))
            {
                return Ok(Some(m));
            }
        }
        Ok(None)
    }

    /// Sign with a key on the card and encrypt to one or more recipients.
    ///
    /// Card-backed counterpart to [`sign_and_encrypt_to_recipients`]. The
    /// signer's matching key MUST live in the card's signing slot;
    /// `signer_public_key` is the public material the keystore holds for it.
    pub fn sign_and_encrypt_on_card_to_recipients(
        store: &KeyStore,
        signer_public_key: &[u8],
        pin: &Pin,
        ident: Option<&str>,
        recipients: &[&str],
        plaintext: &[u8],
        armor: bool,
    ) -> Result<Vec<u8>> {
        let mut key_data_list: Vec<Vec<u8>> = Vec::new();
        for id in recipients {
            let (data, info) = store::resolve_recipient(store, id)?;
            store::ensure_key_usable_for_encryption(&info)?;
            key_data_list.push(data);
        }
        let key_refs: Vec<&[u8]> = key_data_list.iter().map(|d| d.as_slice()).collect();

        wecanencrypt::card::sign_and_encrypt_to_multiple_on_card(
            signer_public_key,
            pin.as_slice(),
            ident,
            &key_refs,
            plaintext,
            armor,
        )
        .map_err(|e| Error::Card(format!("sign_and_encrypt_to_multiple_on_card: {e}")))
    }
}

#[cfg(feature = "card")]
pub use card_encryption::{find_signing_card_for_encrypt, sign_and_encrypt_on_card_to_recipients};

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, KeyStore};

    fn pw(s: &str) -> crate::Passphrase {
        crate::Passphrase::new(s.to_string())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        let fp = store.import_key(&alice.secret_key).unwrap();

        let ct = encrypt_to_recipients(&store, &[&fp], b"hello", true).unwrap();
        let pt = wecanencrypt::decrypt_bytes(&alice.secret_key, &ct, "pw").unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn encrypt_rejects_unknown_recipient() {
        let store = KeyStore::open_in_memory().unwrap();
        let err = encrypt_to_recipients(
            &store,
            &["0000000000000000000000000000000000000000"],
            b"hello",
            true,
        )
        .unwrap_err();
        assert!(matches!(err, Error::KeyNotFound(_)));
    }

    #[test]
    fn encrypt_by_email_allows_public_only_recipient() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let ct = encrypt_to_recipients(&store, &["alice@example.com"], b"hello", true).unwrap();
        let pt = wecanencrypt::decrypt_bytes(&alice.secret_key, &ct, "pw").unwrap();
        assert_eq!(pt, b"hello");
    }

    /// Software sign-then-encrypt round-trip via the new keystore-aware
    /// wrapper. Verifies that the recipient sees the plaintext and that the
    /// inner signature carries the signer's fingerprint.
    #[test]
    fn sign_and_encrypt_software_roundtrip() {
        let alice = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        // Bob is the recipient (his secret key is in the store so we can
        // decrypt below); Alice's public key is in the store so the
        // recipient classifier works on the encrypted-to side.
        store.import_key(&bob.secret_key).unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let ct = sign_and_encrypt_to_recipients(
            &store,
            &alice.secret_key,
            &pw("alice-pw"),
            &["bob@example.com"],
            b"hello, signed and sealed",
            true,
        )
        .unwrap();

        let result = crate::decrypt::decrypt_and_verify_with_key(
            &store,
            &bob.secret_key,
            &ct,
            &pw("bob-pw"),
        )
        .unwrap();
        assert_eq!(result.plaintext.as_slice(), b"hello, signed and sealed");
        match result.outcome {
            crate::decrypt::DecryptVerifyOutcome::Good { key_info, .. } => {
                assert!(key_info
                    .user_ids
                    .iter()
                    .any(|u| u.value.contains("alice@example.com")));
            }
            other => panic!("expected Good, got {other:?}"),
        }
    }
}
