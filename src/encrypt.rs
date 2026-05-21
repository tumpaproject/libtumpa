//! Encryption.

use wecanencrypt::KeyStore;

use crate::error::{Error, Result};
use crate::store;

/// Resolve recipient IDs to their public-key bytes, validating each with
/// [`store::ensure_key_usable_for_encryption`]. Shared by the software and
/// card sign+encrypt entry points so the validation rules stay in one place.
fn resolve_recipient_keys(store: &KeyStore, recipients: &[&str]) -> Result<Vec<Vec<u8>>> {
    let mut key_data_list: Vec<Vec<u8>> = Vec::with_capacity(recipients.len());
    for id in recipients {
        let (data, info) = store::resolve_recipient(store, id)?;
        store::ensure_key_usable_for_encryption(&info)?;
        key_data_list.push(data);
    }
    Ok(key_data_list)
}

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
    let key_data_list = resolve_recipient_keys(store, recipients)?;
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
    let key_data_list = resolve_recipient_keys(store, recipients)?;
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

/// Sign-and-encrypt with a mixed visible/hidden recipient set.
///
/// `visible_recipients` are encoded as standard PKESK packets exposing
/// their key id. `hidden_recipients` are encoded as PKESK packets with the
/// recipient key id replaced by the all-zero wildcard (RFC 4880
/// `throw-keyid` / `--hidden-recipient`).
///
/// This is the libtumpa-level primitive that mail clients use to deliver
/// "Bcc with encryption" without leaking Bcc identities to the To/Cc
/// recipients. Every recipient — visible or hidden — receives the same
/// ciphertext and decrypts to the same plaintext.
///
/// At least one recipient must be supplied across the two lists. Every
/// recipient is resolved via [`store::resolve_recipient`] and validated
/// with [`store::ensure_key_usable_for_encryption`] before encryption.
pub fn sign_and_encrypt_to_recipients_with_hidden(
    store: &KeyStore,
    signer_key_data: &[u8],
    passphrase: &crate::Passphrase,
    visible_recipients: &[&str],
    hidden_recipients: &[&str],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let visible_data = resolve_recipient_keys(store, visible_recipients)?;
    let hidden_data = resolve_recipient_keys(store, hidden_recipients)?;
    let visible_refs: Vec<&[u8]> = visible_data.iter().map(|d| d.as_slice()).collect();
    let hidden_refs: Vec<&[u8]> = hidden_data.iter().map(|d| d.as_slice()).collect();

    wecanencrypt::sign_and_encrypt_to_multiple_with_hidden(
        signer_key_data,
        passphrase.as_str(),
        &visible_refs,
        &hidden_refs,
        plaintext,
        armor,
    )
    .map_err(|e| Error::Encrypt(format!("sign_and_encrypt_to_multiple_with_hidden: {e}")))
}

/// Encrypt (no signature) with a mixed visible/hidden recipient set.
/// Sibling of [`sign_and_encrypt_to_recipients_with_hidden`].
pub fn encrypt_to_recipients_with_hidden(
    store: &KeyStore,
    visible_recipients: &[&str],
    hidden_recipients: &[&str],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let visible_data = resolve_recipient_keys(store, visible_recipients)?;
    let hidden_data = resolve_recipient_keys(store, hidden_recipients)?;
    let visible_refs: Vec<&[u8]> = visible_data.iter().map(|d| d.as_slice()).collect();
    let hidden_refs: Vec<&[u8]> = hidden_data.iter().map(|d| d.as_slice()).collect();

    wecanencrypt::encrypt_bytes_to_multiple_with_hidden(
        &visible_refs,
        &hidden_refs,
        plaintext,
        armor,
    )
    .map_err(|e| Error::Encrypt(format!("encrypt_bytes_to_multiple_with_hidden: {e}")))
}

#[cfg(feature = "card")]
mod card_encryption {
    use super::*;
    use crate::Pin;
    use wecanencrypt::card::CardKeyMatch;

    /// Find a connected card whose signing slot matches `signer_public_key`.
    /// Reuses [`crate::sign::find_signing_card`] so card selection behavior
    /// stays consistent with the signing path.
    pub fn find_signing_card_for_encrypt(signer_public_key: &[u8]) -> Result<Option<CardKeyMatch>> {
        crate::sign::find_signing_card(signer_public_key)
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
        let key_data_list = resolve_recipient_keys(store, recipients)?;
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

    /// Card-backed sign-and-encrypt to a mixed visible/hidden recipient set.
    ///
    /// Sibling of
    /// [`crate::encrypt::sign_and_encrypt_to_recipients_with_hidden`] with
    /// the signer key living on a smartcard. Hidden recipients have their
    /// PKESK key id blanked to the all-zero wildcard (RFC 4880
    /// `throw-keyid`).
    // Visible + hidden recipient lists genuinely belong as separate
    // arguments (Bcc vs To/Cc, threaded straight through to the matching
    // wecanencrypt card primitive). Bundling them into a struct just to
    // appease clippy's 7-arg ceiling would add an indirection layer with
    // no real ergonomic win.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_and_encrypt_on_card_to_recipients_with_hidden(
        store: &KeyStore,
        signer_public_key: &[u8],
        pin: &Pin,
        ident: Option<&str>,
        visible_recipients: &[&str],
        hidden_recipients: &[&str],
        plaintext: &[u8],
        armor: bool,
    ) -> Result<Vec<u8>> {
        let visible_data = resolve_recipient_keys(store, visible_recipients)?;
        let hidden_data = resolve_recipient_keys(store, hidden_recipients)?;
        let visible_refs: Vec<&[u8]> = visible_data.iter().map(|d| d.as_slice()).collect();
        let hidden_refs: Vec<&[u8]> = hidden_data.iter().map(|d| d.as_slice()).collect();

        wecanencrypt::card::sign_and_encrypt_to_multiple_on_card_with_hidden(
            signer_public_key,
            pin.as_slice(),
            ident,
            &visible_refs,
            &hidden_refs,
            plaintext,
            armor,
        )
        .map_err(|e| {
            Error::Card(format!(
                "sign_and_encrypt_to_multiple_on_card_with_hidden: {e}"
            ))
        })
    }
}

#[cfg(feature = "card")]
pub use card_encryption::{
    find_signing_card_for_encrypt, sign_and_encrypt_on_card_to_recipients,
    sign_and_encrypt_on_card_to_recipients_with_hidden,
};

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

    /// Bcc-style hidden recipient round-trip via the keystore-aware
    /// `sign_and_encrypt_to_recipients_with_hidden`. Bob (visible) decrypts
    /// successfully; Carol (hidden) ALSO decrypts successfully; and the
    /// ciphertext's PKESK packets show exactly one wildcard key id (Carol)
    /// — so a To/Cc recipient running `gpg --list-packets` cannot learn
    /// who the Bcc recipient was.
    #[test]
    fn sign_and_encrypt_with_hidden_routes_bcc_through_wildcard_pkesk() {
        let alice = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let carol = create_key_simple("carol-pw", &["Carol <carol@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();
        store.import_key(bob.public_key.as_bytes()).unwrap();
        store.import_key(carol.public_key.as_bytes()).unwrap();

        let ct = sign_and_encrypt_to_recipients_with_hidden(
            &store,
            &alice.secret_key,
            &pw("alice-pw"),
            &["bob@example.com"],
            &["carol@example.com"],
            b"hidden-bcc payload",
            true,
        )
        .expect("encrypt with hidden bcc");

        // Bob (visible) decrypts.
        let pt_bob = wecanencrypt::decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap();
        assert_eq!(pt_bob, b"hidden-bcc payload");

        // Carol (hidden) decrypts the SAME ciphertext.
        let pt_carol = wecanencrypt::decrypt_bytes(&carol.secret_key, &ct, "carol-pw").unwrap();
        assert_eq!(pt_carol, b"hidden-bcc payload");

        // The PKESK enumeration shows exactly one wildcard key id —
        // Carol's identity is not on the wire.
        let key_ids = wecanencrypt::bytes_encrypted_for(&ct).expect("enumerate PKESKs");
        assert_eq!(key_ids.len(), 2, "expected 2 PKESKs, got {:?}", key_ids);
        let wildcard = "0000000000000000";
        assert_eq!(
            key_ids
                .iter()
                .filter(|id| id.eq_ignore_ascii_case(wildcard))
                .count(),
            1,
            "expected exactly one wildcard PKESK (Carol Bcc), got {:?}",
            key_ids
        );
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
