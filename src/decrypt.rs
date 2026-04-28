//! Decryption with optional card-first dispatch.
//!
//! Ported from `tumpa-cli/src/gpg/decrypt.rs` with prompting stripped.

use wecanencrypt::{DecryptVerifySignature, KeyInfo, KeyStore};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::store;
use crate::Passphrase;

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
    passphrase: &Passphrase,
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = wecanencrypt::decrypt_bytes(key_data, ciphertext, passphrase.as_str())
        .map_err(|e| Error::Decrypt(format!("decrypt_bytes: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

/// Outcome of [`decrypt_and_verify_with_key`].
///
/// Distinct from [`crate::verify::VerifyOutcome`] in two ways: the
/// `Unsigned` variant is needed for the encrypt-only case, and `Good`
/// surfaces both the signer's [`KeyInfo`] and the specific subkey
/// fingerprint that produced the signature, so the caller can render
/// "signed by Alice (subkey 0xABCD…)" without re-querying the store.
#[derive(Debug, Clone)]
pub enum DecryptVerifyOutcome {
    /// Ciphertext was encrypt-only; no signature to check.
    Unsigned,
    /// Ciphertext was sign-then-encrypted, signer found in the keystore,
    /// and the inner signature verified.
    Good {
        key_info: KeyInfo,
        /// Verifier fingerprint pulled from the signature; may be the
        /// fingerprint of the primary key or of a signing subkey.
        verifier_fingerprint: String,
    },
    /// Ciphertext was sign-then-encrypted, signer key was in the
    /// keystore, but the inner signature failed to verify.
    Bad { key_info: KeyInfo },
    /// Ciphertext was sign-then-encrypted, but no signer is present in
    /// the keystore.
    UnknownKey {
        /// Issuer ids extracted from the inner signature, uppercase hex
        /// (40-char fingerprints and/or 16-char key ids).
        issuer_ids: Vec<String>,
    },
}

/// Decrypt-and-verify result from [`decrypt_and_verify_with_key`].
pub struct DecryptVerifyResult {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub outcome: DecryptVerifyOutcome,
}

// Hand-written Debug to redact plaintext — `Zeroizing<Vec<u8>>` happily
// hex-dumps the cleartext into logs otherwise, defeating its whole point.
impl std::fmt::Debug for DecryptVerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptVerifyResult")
            .field("plaintext", &format!("<{} bytes redacted>", self.plaintext.len()))
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Decrypt `ciphertext` with a software secret key, and if the inner
/// payload was sign-then-encrypted, look up the signer in `store` and
/// verify the inner signature.
///
/// This is the primitive a Mail extension uses for the common
/// "signed and encrypted" PGP/MIME message: one call returns plaintext
/// plus a typed signature outcome that maps cleanly to the lock /
/// checkmark UI in the mail client.
pub fn decrypt_and_verify_with_key(
    store: &KeyStore,
    key_data: &[u8],
    ciphertext: &[u8],
    passphrase: &Passphrase,
) -> Result<DecryptVerifyResult> {
    // Capture the resolved (cert_bytes, key_info) for whichever issuer
    // matched, so that on Good/Bad we can return the KeyInfo without
    // re-resolving. The closure runs synchronously inside the wecanencrypt
    // call, so a `RefCell`-style indirection isn't needed; we capture
    // into a mutable local via `&mut` over the closure.
    let mut resolved_signer: Option<KeyInfo> = None;

    let result = wecanencrypt::decrypt_and_verify(
        key_data,
        ciphertext,
        passphrase.as_str(),
        |issuer_ids| match store::resolve_from_issuer_ids(store, issuer_ids) {
            Ok(Some((cert_bytes, key_info))) => {
                resolved_signer = Some(key_info);
                Some(cert_bytes)
            }
            _ => None,
        },
    )
    .map_err(|e| Error::Decrypt(format!("decrypt_and_verify: {e}")))?;

    let outcome = match result.signature {
        DecryptVerifySignature::Unsigned => DecryptVerifyOutcome::Unsigned,
        DecryptVerifySignature::Good {
            verifier_fingerprint,
        } => {
            // Wecanencrypt only invokes the resolver when there's a
            // signature to verify, so on Good we always have a KeyInfo.
            // If somehow we don't, fall through to UnknownKey rather than
            // panic.
            match resolved_signer {
                Some(key_info) => DecryptVerifyOutcome::Good {
                    key_info,
                    verifier_fingerprint,
                },
                None => DecryptVerifyOutcome::UnknownKey {
                    issuer_ids: vec![verifier_fingerprint],
                },
            }
        }
        DecryptVerifySignature::Bad => match resolved_signer {
            Some(key_info) => DecryptVerifyOutcome::Bad { key_info },
            None => DecryptVerifyOutcome::UnknownKey {
                issuer_ids: Vec::new(),
            },
        },
        DecryptVerifySignature::UnknownKey { issuer_ids } => {
            DecryptVerifyOutcome::UnknownKey { issuer_ids }
        }
    };

    Ok(DecryptVerifyResult {
        plaintext: Zeroizing::new(result.plaintext),
        outcome,
    })
}

#[cfg(feature = "card")]
mod card_decryption {
    use super::*;
    use crate::Pin;
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

    /// Decrypt `ciphertext` on a connected card. Pass `ident` to bind to a
    /// specific card when multiple cards are connected.
    pub fn decrypt_on_card(
        key_data: &[u8],
        ciphertext: &[u8],
        pin: &Pin,
        ident: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext =
            wecanencrypt::card::decrypt_bytes_on_card(ciphertext, key_data, pin.as_slice(), ident)
                .map_err(|e| Error::Card(format!("decrypt_bytes_on_card: {e}")))?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(feature = "card")]
pub use card_decryption::{decrypt_on_card, find_decryption_card, DecryptionCard};

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{
        create_key_simple, encrypt_bytes, sign_and_encrypt_to_multiple, KeyStore,
    };

    fn pw(s: &str) -> Passphrase {
        Passphrase::new(s.to_string())
    }

    #[test]
    fn decrypt_and_verify_with_key_unsigned() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();

        let ct = encrypt_bytes(alice.public_key.as_bytes(), b"hello", true).unwrap();

        let result =
            decrypt_and_verify_with_key(&store, &alice.secret_key, &ct, &pw("pw")).unwrap();
        assert_eq!(result.plaintext.as_slice(), b"hello");
        assert!(matches!(result.outcome, DecryptVerifyOutcome::Unsigned));
    }

    #[test]
    fn decrypt_and_verify_with_key_good() {
        let alice = create_key_simple("alice-pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <b@example.com>"]).unwrap();

        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&bob.secret_key).unwrap();
        // Alice's public key is what we'd have for incoming mail.
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let ct = sign_and_encrypt_to_multiple(
            &alice.secret_key,
            "alice-pw",
            &[bob.public_key.as_bytes()],
            b"signed and sealed",
            true,
        )
        .unwrap();

        let result =
            decrypt_and_verify_with_key(&store, &bob.secret_key, &ct, &pw("bob-pw")).unwrap();
        assert_eq!(result.plaintext.as_slice(), b"signed and sealed");
        match result.outcome {
            DecryptVerifyOutcome::Good {
                key_info,
                verifier_fingerprint,
            } => {
                // KeyInfo must be Alice's, and the verifier fingerprint must
                // be a 40-char hex (subkey or primary).
                assert!(key_info
                    .user_ids
                    .iter()
                    .any(|u| u.value.contains("a@example.com")));
                assert_eq!(verifier_fingerprint.len(), 40);
            }
            other => panic!("expected Good, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_and_verify_with_key_unknown_signer() {
        let alice = create_key_simple("alice-pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <b@example.com>"]).unwrap();

        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&bob.secret_key).unwrap();
        // Alice's pubkey deliberately NOT imported.

        let ct = sign_and_encrypt_to_multiple(
            &alice.secret_key,
            "alice-pw",
            &[bob.public_key.as_bytes()],
            b"signed by alice",
            true,
        )
        .unwrap();

        let result =
            decrypt_and_verify_with_key(&store, &bob.secret_key, &ct, &pw("bob-pw")).unwrap();
        match result.outcome {
            DecryptVerifyOutcome::UnknownKey { issuer_ids } => {
                assert!(!issuer_ids.is_empty());
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_and_verify_with_key_wrong_passphrase() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();
        let ct = encrypt_bytes(alice.public_key.as_bytes(), b"hello", true).unwrap();

        let err = decrypt_and_verify_with_key(&store, &alice.secret_key, &ct, &pw("wrong"))
            .unwrap_err();
        assert!(err.to_string().contains("decrypt"));
    }

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
        let pw = Passphrase::new("pw".to_string());
        let pt = decrypt_with_key(&key_data, &ct, &pw).unwrap();
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
