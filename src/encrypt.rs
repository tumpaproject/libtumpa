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

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, KeyStore};

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
}
