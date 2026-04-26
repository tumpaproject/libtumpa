//! Signature verification.
//!
//! Ported from `tumpa-cli/src/gpg/verify.rs` minus the `[GNUPG:]` stderr
//! formatting (tumpa-cli's shim keeps that for git).
//!
//! # Caller responsibility: UID sanitization
//!
//! UIDs inside a returned [`KeyInfo`] are raw OpenPGP strings and may
//! contain any Unicode codepoint, including control characters and
//! newlines. libtumpa does **not** sanitize them because the correct
//! sanitization depends on the caller's output format (git status
//! stream, Tauri IPC JSON, shell, log file, etc.).
//!
//! Callers that emit UIDs into line-based protocols — notably git's
//! `[GNUPG:]` status stream on stdout — **must** strip control
//! characters first. Use [`sanitize_uid_for_status`] for this case.
//!
//! The attack this prevents: a key with a UID
//! `"Attacker <x@y>\n[GNUPG:] VALIDSIG <fake-fingerprint>"` would, if
//! written unsanitized into git's GPG status stream, convince git the
//! signature was trusted under a different fingerprint.

use std::io::Cursor;

use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey,
};
use pgp::types::KeyDetails;
use wecanencrypt::{KeyInfo, KeyStore};

use crate::error::{Error, Result};
use crate::store;

/// Outcome of verifying a detached signature.
///
/// See the [module docs](self) for the caller's UID-sanitization
/// responsibility before emitting any `user_ids[i].value` into
/// line-based output.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// Signer was found in the keystore and the signature is valid.
    Good {
        key_info: KeyInfo,
        /// Verifier fingerprint taken from the signature (may be subkey FP).
        verifier_fingerprint: String,
    },
    /// Signer was found but the signature is invalid.
    Bad { key_info: KeyInfo },
    /// Signer was not found in the keystore.
    UnknownKey {
        /// 16-char key ID derived from the signature's issuer info.
        key_id: String,
    },
}

/// Strip control characters from an OpenPGP UID before emitting it into
/// line-based output (`[GNUPG:]` status lines, shell output, IPC, logs).
///
/// See the [module docs](self) for the attack this prevents.
///
/// ```
/// use libtumpa::verify::sanitize_uid_for_status;
/// let malicious = "Evil <x@y>\n[GNUPG:] VALIDSIG fake";
/// assert_eq!(
///     sanitize_uid_for_status(malicious),
///     "Evil <x@y>[GNUPG:] VALIDSIG fake",
/// );
/// ```
pub fn sanitize_uid_for_status(uid: &str) -> String {
    uid.chars().filter(|c| !c.is_control()).collect()
}

/// Parse a detached signature (armored or binary).
pub fn parse_detached(sig_bytes: &[u8]) -> Result<DetachedSignature> {
    if let Ok((sig, _)) = DetachedSignature::from_armor_single(Cursor::new(sig_bytes)) {
        return Ok(sig);
    }
    DetachedSignature::from_bytes(Cursor::new(sig_bytes))
        .map_err(|e| Error::Verify(format!("failed to parse detached signature: {e}")))
}

/// Verify a detached signature against `data`, looking the signer up in the
/// supplied keystore.
pub fn verify_detached(store: &KeyStore, data: &[u8], sig_bytes: &[u8]) -> Result<VerifyOutcome> {
    let detached = parse_detached(sig_bytes)?;
    let sig_config = detached
        .signature
        .config()
        .ok_or_else(|| Error::Verify("signature has no config".into()))?;

    let issuer_ids = store::extract_issuer_ids(sig_config);
    if issuer_ids.is_empty() {
        return Err(Error::Verify(
            "signature has no issuer fingerprint or key ID".into(),
        ));
    }

    let lookup = store::resolve_from_issuer_ids(store, &issuer_ids)?;
    let Some((cert_data, cert_info)) = lookup else {
        let key_id = issuer_key_id_for_display(&issuer_ids);
        return Ok(VerifyOutcome::UnknownKey { key_id });
    };

    let valid = wecanencrypt::verify_bytes_detached(&cert_data, data, sig_bytes).unwrap_or(false);

    if valid {
        let verifier_fp = issuer_ids
            .iter()
            .find(|id| id.len() == 40)
            .cloned()
            .unwrap_or_else(|| cert_info.fingerprint.clone())
            .to_uppercase();
        Ok(VerifyOutcome::Good {
            key_info: cert_info,
            verifier_fingerprint: verifier_fp,
        })
    } else {
        Ok(VerifyOutcome::Bad {
            key_info: cert_info,
        })
    }
}

/// Verify a cleartext-signed (`-----BEGIN PGP SIGNED MESSAGE-----`) message
/// by looking the signer(s) up in `store`.
///
/// Only cleartext-signed messages are supported on the keystore-lookup
/// path. For binary or armored inline-signed messages (the kind produced
/// by `gpg --sign` without `--clearsign`), the caller must supply the
/// public key directly via `wecanencrypt::verify_bytes` instead.
///
/// **Multi-signature messages.** A cleartext-signed block may carry more
/// than one signature. We iterate the signatures, try to resolve the
/// signer for each, and return [`VerifyOutcome::Good`] on the *first*
/// signature that verifies against a key in the store. Only when every
/// signature was either by an unknown signer or failed to verify do we
/// return [`VerifyOutcome::Bad`] (preferred) or
/// [`VerifyOutcome::UnknownKey`] (if no signer was resolvable at all).
pub fn verify_inline(store: &KeyStore, signed_message: &[u8]) -> Result<VerifyOutcome> {
    let text = std::str::from_utf8(signed_message)
        .map_err(|_| Error::Verify("cleartext-signed message must be valid UTF-8".into()))?;

    let (msg, _) = CleartextSignedMessage::from_string(text)
        .map_err(|e| Error::Verify(format!("failed to parse cleartext-signed message: {e}")))?;

    let signatures = msg.signatures();
    if signatures.is_empty() {
        return Err(Error::Verify(
            "cleartext-signed message has no signature".into(),
        ));
    }
    let normalized_text = msg.signed_text();

    // Track outcomes across all embedded signatures so that, if no
    // signature verifies, we can still report the most useful failure
    // shape: BAD (signer known, signature did not verify) wins over
    // UnknownKey (no signer resolvable in the store).
    let mut saw_issuer = false;
    let mut first_bad: Option<KeyInfo> = None;
    let mut first_unknown_key_id: Option<String> = None;

    for sig in signatures {
        let Some(cfg) = sig.config() else { continue };

        let mut issuer_ids: Vec<String> = Vec::new();
        for id in store::extract_issuer_ids(cfg) {
            if !issuer_ids.contains(&id) {
                issuer_ids.push(id);
            }
        }
        if issuer_ids.is_empty() {
            continue;
        }
        saw_issuer = true;

        let lookup = store::resolve_from_issuer_ids(store, &issuer_ids)?;
        let Some((cert_data, cert_info)) = lookup else {
            if first_unknown_key_id.is_none() {
                first_unknown_key_id = Some(issuer_key_id_for_display(&issuer_ids));
            }
            continue;
        };

        let cert = parse_verifying_cert(&cert_data)?;
        if verify_signature_with_cert(&cert, &issuer_ids, sig, normalized_text.as_bytes()) {
            let verifier_fp = issuer_ids
                .iter()
                .find(|id| id.len() == 40)
                .cloned()
                .unwrap_or_else(|| cert_info.fingerprint.clone())
                .to_uppercase();
            return Ok(VerifyOutcome::Good {
                key_info: cert_info,
                verifier_fingerprint: verifier_fp,
            });
        }
        if first_bad.is_none() {
            first_bad = Some(cert_info);
        }
    }

    if !saw_issuer {
        return Err(Error::Verify(
            "cleartext-signed message has no issuer fingerprint or key ID".into(),
        ));
    }

    if let Some(key_info) = first_bad {
        Ok(VerifyOutcome::Bad { key_info })
    } else {
        Ok(VerifyOutcome::UnknownKey {
            key_id: first_unknown_key_id.unwrap_or_default(),
        })
    }
}

/// Pick a displayable key-id form from a list of issuer IDs (16-char key
/// IDs, 40-char fingerprints, or hex of either).
fn issuer_key_id_for_display(issuer_ids: &[String]) -> String {
    if let Some(kid) = issuer_ids.iter().find(|id| id.len() == 16) {
        return kid.to_uppercase();
    }
    if let Some(fp) = issuer_ids.iter().find(|id| id.len() == 40) {
        return fp[24..].to_uppercase();
    }
    issuer_ids
        .first()
        .map(|s| s.to_uppercase())
        .unwrap_or_default()
}

fn parse_verifying_cert(cert_data: &[u8]) -> Result<SignedPublicKey> {
    if let Ok((cert, _headers)) = SignedPublicKey::from_reader_single(Cursor::new(cert_data)) {
        return Ok(cert);
    }

    let (secret, _headers) = SignedSecretKey::from_reader_single(Cursor::new(cert_data))
        .map_err(|e| Error::KeyStore(format!("failed to parse signer cert from keystore: {e}")))?;
    Ok(secret.into())
}

fn verify_signature_with_cert(
    cert: &SignedPublicKey,
    issuer_ids: &[String],
    sig: &pgp::packet::Signature,
    normalized_text: &[u8],
) -> bool {
    if issuer_matches_key(
        issuer_ids,
        &hex::encode(cert.primary_key.fingerprint().as_bytes()).to_uppercase(),
        &hex::encode(cert.primary_key.legacy_key_id()).to_uppercase(),
    ) && sig.verify(&cert.primary_key, normalized_text).is_ok()
    {
        return true;
    }

    cert.public_subkeys.iter().any(|subkey| {
        issuer_matches_key(
            issuer_ids,
            &hex::encode(subkey.fingerprint().as_bytes()).to_uppercase(),
            &hex::encode(subkey.legacy_key_id()).to_uppercase(),
        ) && sig.verify(subkey, normalized_text).is_ok()
    })
}

fn issuer_matches_key(issuer_ids: &[String], fingerprint: &str, key_id: &str) -> bool {
    issuer_ids.iter().any(|id| {
        let id = id.to_uppercase();
        id == fingerprint || id == key_id
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, KeyStore};

    #[test]
    fn verify_good_signature() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&key.secret_key).unwrap();

        let sig = wecanencrypt::sign_bytes_detached(&key.secret_key, b"hello", "pw").unwrap();
        let outcome = verify_detached(&store, b"hello", sig.as_bytes()).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Good { .. }));
    }

    #[test]
    fn verify_unknown_key() {
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        // Alice's key is NOT imported into the store.

        let sig = wecanencrypt::sign_bytes_detached(&alice.secret_key, b"hello", "pw").unwrap();
        let outcome = verify_detached(&store, b"hello", sig.as_bytes()).unwrap();
        assert!(matches!(outcome, VerifyOutcome::UnknownKey { .. }));
    }

    #[test]
    fn sanitize_uid_strips_control_chars() {
        // Newline is the injection vector for [GNUPG:] forgery.
        let injected = "Evil <x@y>\n[GNUPG:] VALIDSIG fake-fingerprint";
        let out = sanitize_uid_for_status(injected);
        assert!(!out.contains('\n'));
        assert_eq!(out, "Evil <x@y>[GNUPG:] VALIDSIG fake-fingerprint");

        // Also strip carriage returns and other C0 controls.
        let weird = "A\r\t\x07\x1bB";
        assert_eq!(sanitize_uid_for_status(weird), "AB");

        // Benign UIDs pass through unchanged.
        assert_eq!(
            sanitize_uid_for_status("Alice <alice@example.com>"),
            "Alice <alice@example.com>"
        );
    }

    #[test]
    fn verify_bad_signature() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&key.secret_key).unwrap();

        let sig = wecanencrypt::sign_bytes_detached(&key.secret_key, b"hello", "pw").unwrap();
        // Verify against different data
        let outcome = verify_detached(&store, b"tampered", sig.as_bytes()).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Bad { .. }));
    }

    #[test]
    fn verify_inline_good() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&key.secret_key).unwrap();

        let signed = wecanencrypt::sign_bytes_cleartext(&key.secret_key, b"hello\n", "pw").unwrap();
        let outcome = verify_inline(&store, &signed).unwrap();
        match outcome {
            VerifyOutcome::Good { key_info, .. } => {
                assert!(key_info
                    .user_ids
                    .iter()
                    .any(|u| u.value.contains("alice@example.com")));
            }
            other => panic!("expected Good, got {other:?}"),
        }
    }

    #[test]
    fn verify_inline_unknown_key() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        // Alice's key is NOT imported.

        let signed =
            wecanencrypt::sign_bytes_cleartext(&alice.secret_key, b"hello\n", "pw").unwrap();
        let outcome = verify_inline(&store, &signed).unwrap();
        assert!(matches!(outcome, VerifyOutcome::UnknownKey { .. }));
    }

    #[test]
    fn verify_inline_bad_signature() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&key.secret_key).unwrap();

        let signed = wecanencrypt::sign_bytes_cleartext(&key.secret_key, b"hello\n", "pw").unwrap();
        // Tamper the signed text inside the cleartext block. Replace
        // "hello" with "HELLO" — payload region only, signature block
        // untouched, so the parser still accepts it but verification
        // must fail.
        let mut tampered = signed.clone();
        if let Some(pos) = tampered.windows(5).position(|w| w == b"hello") {
            tampered[pos..pos + 5].copy_from_slice(b"HELLO");
        } else {
            panic!("test fixture: did not find 'hello' to tamper");
        }
        let outcome = verify_inline(&store, &tampered).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Bad { .. }));
    }

    #[test]
    fn verify_inline_rejects_non_cleartext() {
        let store = KeyStore::open_in_memory().unwrap();
        let err = verify_inline(&store, b"this is not a cleartext signed message").unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }
}
