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

use pgp::composed::{Deserializable, DetachedSignature};
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
        let key_id = if let Some(kid) = issuer_ids.iter().find(|id| id.len() == 16) {
            kid.to_uppercase()
        } else if let Some(fp) = issuer_ids.iter().find(|id| id.len() == 40) {
            fp[24..].to_uppercase()
        } else {
            issuer_ids
                .first()
                .map(|s| s.to_uppercase())
                .unwrap_or_default()
        };
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
}
