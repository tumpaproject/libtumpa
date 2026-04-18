//! Decryption with optional card-first dispatch.
//!
//! Ported from `tumpa-cli/src/gpg/decrypt.rs` with prompting stripped.

use wecanencrypt::{KeyInfo, KeyStore};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Key IDs a ciphertext is encrypted for.
pub fn recipients_of(ciphertext: &[u8]) -> Result<Vec<String>> {
    wecanencrypt::bytes_encrypted_for(ciphertext)
        .map_err(|e| Error::Decrypt(format!("bytes_encrypted_for: {e}")))
}

/// Find a software secret key in the store that can decrypt this ciphertext.
/// Returns `None` if no matching secret key is present.
pub fn find_software_decryption_key(
    store: &KeyStore,
    ciphertext: &[u8],
) -> Result<Option<(Vec<u8>, KeyInfo)>> {
    let key_ids = recipients_of(ciphertext)?;
    for kid in &key_ids {
        if let Ok(Some(data)) = store.find_by_key_id(kid) {
            let info = wecanencrypt::parse_key_bytes(&data, true)?;
            if info.is_secret {
                return Ok(Some((data, info)));
            }
        }
    }
    Ok(None)
}

/// Decrypt `ciphertext` with a software secret key.
pub fn decrypt_with_key(
    key_data: &[u8],
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = wecanencrypt::decrypt_bytes(key_data, ciphertext, passphrase)
        .map_err(|e| Error::Decrypt(format!("decrypt_bytes: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(feature = "card")]
mod card_decryption {
    use super::*;
    use wecanencrypt::card::{get_card_details, list_all_cards, CardSummary};

    /// Describes a card that can decrypt a particular ciphertext.
    pub struct DecryptionCard {
        pub card: CardSummary,
        pub encryption_fingerprint: String,
        pub key_data: Vec<u8>,
        pub key_info: KeyInfo,
    }

    /// Search connected cards for one whose encryption slot matches this
    /// ciphertext's recipients and whose secret key material is in `store`.
    pub fn find_decryption_card(
        store: &KeyStore,
        ciphertext: &[u8],
    ) -> Result<Option<DecryptionCard>> {
        let key_ids = recipients_of(ciphertext)?;
        let cards = list_all_cards().map_err(|e| Error::Card(e.to_string()))?;

        for card in cards {
            let info = match get_card_details(Some(&card.ident)) {
                Ok(i) => i,
                Err(_) => continue,
            };

            let Some(enc_fp) = info.encryption_fingerprint.clone() else {
                continue;
            };
            let enc_fp_upper = enc_fp.to_uppercase();
            let enc_kid = if enc_fp_upper.len() >= 16 {
                &enc_fp_upper[enc_fp_upper.len() - 16..]
            } else {
                enc_fp_upper.as_str()
            };
            let matches = key_ids.iter().any(|kid| kid.to_uppercase() == enc_kid);
            if !matches {
                continue;
            }

            if let Ok(Some(key_data)) = store.find_by_subkey_fingerprint(&enc_fp_upper) {
                let key_info = wecanencrypt::parse_key_bytes(&key_data, false)?;
                return Ok(Some(DecryptionCard {
                    card,
                    encryption_fingerprint: enc_fp_upper,
                    key_data,
                    key_info,
                }));
            }
        }

        Ok(None)
    }

    /// Decrypt `ciphertext` on a connected card.
    pub fn decrypt_on_card(
        key_data: &[u8],
        ciphertext: &[u8],
        pin: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = wecanencrypt::card::decrypt_bytes_on_card(ciphertext, key_data, pin)
            .map_err(|e| Error::Card(format!("decrypt_bytes_on_card: {e}")))?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(feature = "card")]
pub use card_decryption::{decrypt_on_card, find_decryption_card, DecryptionCard};

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, encrypt_bytes, KeyStore};

    #[test]
    fn recipients_of_returns_key_ids() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let ct = encrypt_bytes(alice.public_key.as_bytes(), b"hello", true).unwrap();
        let kids = recipients_of(&ct).unwrap();
        assert!(!kids.is_empty());
    }

    #[test]
    fn find_software_decryption_key_matches() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();

        let ct = encrypt_bytes(alice.public_key.as_bytes(), b"hello", true).unwrap();
        let found = find_software_decryption_key(&store, &ct).unwrap();
        assert!(found.is_some());

        let (key_data, info) = found.unwrap();
        assert!(info.is_secret);
        let pt = decrypt_with_key(&key_data, &ct, "pw").unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn find_software_decryption_key_missing() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        // Key NOT imported.

        let ct = encrypt_bytes(alice.public_key.as_bytes(), b"hello", true).unwrap();
        assert!(find_software_decryption_key(&store, &ct).unwrap().is_none());
    }
}
