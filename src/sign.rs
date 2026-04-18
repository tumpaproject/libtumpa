//! Signing operations.
//!
//! libtumpa provides both the low-level dispatch primitives (sign with
//! software key, sign on card, locate a usable card) and a high-level
//! [`sign_detached`] that drives them, delegating only the passphrase/PIN
//! acquisition to the caller via a closure.
//!
//! The caller (tumpa-cli, tumpa desktop) is responsible for passphrase and
//! PIN entry — libtumpa never prompts.
//!
//! Ported from `tumpa-cli/src/gpg/sign.rs` with the `[GNUPG:]` stderr
//! lines stripped; tumpa-cli's `gpg/` shim keeps those for git.

use wecanencrypt::KeyInfo;

use crate::error::{Error, Result};

/// Sign `data` with a software secret key, producing an armored detached
/// signature.
pub fn sign_detached_with_key(key_data: &[u8], data: &[u8], passphrase: &str) -> Result<String> {
    if passphrase.is_empty() {
        // wecanencrypt will error, but catch it early for a clearer message.
        return Err(Error::Sign("empty passphrase".into()));
    }
    wecanencrypt::sign_bytes_detached(key_data, data, passphrase)
        .map_err(|e| Error::Sign(format!("sign_bytes_detached: {e}")))
}

#[cfg(feature = "card")]
mod card_signing {
    use super::*;
    use wecanencrypt::card::{find_cards_for_key, CardKeyMatch, KeySlot};

    /// Find a connected card that holds a signing-capable slot for this key.
    pub fn find_signing_card(key_data: &[u8]) -> Result<Option<CardKeyMatch>> {
        let matches = find_cards_for_key(key_data).map_err(|e| Error::Card(e.to_string()))?;

        for m in matches {
            let has_signing = m
                .matching_slots
                .iter()
                .any(|s| matches!(s.slot, KeySlot::Signature));
            if has_signing {
                return Ok(Some(m));
            }
        }
        Ok(None)
    }

    /// Sign `data` with a connected OpenPGP card, producing an armored
    /// detached signature. The card must hold a signing-capable subkey
    /// matching `key_data`.
    pub fn sign_detached_on_card(key_data: &[u8], data: &[u8], pin: &[u8]) -> Result<String> {
        wecanencrypt::card::sign_bytes_detached_on_card(data, key_data, pin)
            .map_err(|e| Error::Card(format!("sign_bytes_detached_on_card: {e}")))
    }
}

#[cfg(feature = "card")]
pub use card_signing::{find_signing_card, sign_detached_on_card};

/// Tell a caller which signing backend was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignBackend {
    Card,
    Software,
}

/// A request for a secret during [`sign_detached`].
#[derive(Debug, Clone)]
pub enum SecretRequest<'a> {
    /// Card PIN required. `card_ident` is the card identifier
    /// (`"MANUFACTURER:SERIAL"`).
    CardPin {
        card_ident: &'a str,
        key_info: &'a KeyInfo,
    },
    /// Key passphrase required.
    KeyPassphrase { key_info: &'a KeyInfo },
}

/// Sign `data`, trying a connected card first and falling back to the
/// software key.
///
/// The caller supplies a closure that is invoked whenever libtumpa needs a
/// secret. For card signing, return the PIN bytes; for software signing,
/// return the passphrase string. No pinentry or terminal prompting happens
/// inside libtumpa — the closure is where the caller's UI lives.
///
/// Returns the armored detached signature plus the backend that produced it.
///
/// # Fallback semantics
///
/// If a card matching the key is found but card signing fails (wrong PIN,
/// locked slot, card removed mid-flow, I/O error, caller closure returned
/// an error for `CardPin`), the function falls back to the software key
/// when one is available. The card-side error is logged at `info` level
/// and included in the final `Error::Sign` message if software signing
/// also fails or the key has no secret material.
///
/// If the key is public-only **and** there is no connected card,
/// [`Error::Sign`] is returned.
#[cfg(feature = "card")]
pub fn sign_detached<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    mut secret: F,
) -> Result<(String, SignBackend)>
where
    F: FnMut(SecretRequest<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>>,
{
    let card_attempt: Option<Result<String>> = if let Some(m) = find_signing_card(key_data)? {
        let card_ident = m.card.ident.clone();
        Some(
            secret(SecretRequest::CardPin {
                card_ident: &card_ident,
                key_info,
            })
            .and_then(|pin| sign_detached_on_card(key_data, data, &pin)),
        )
    } else {
        None
    };

    sign_detached_inner(key_data, key_info, data, card_attempt, secret)
}

/// Software-only [`sign_detached`] variant (no card support).
#[cfg(not(feature = "card"))]
pub fn sign_detached<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    mut secret: F,
) -> Result<(String, SignBackend)>
where
    F: FnMut(SecretRequest<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>>,
{
    if !key_info.is_secret {
        return Err(Error::Sign(format!(
            "no secret key available for {}",
            key_info.fingerprint
        )));
    }
    let pass = secret(SecretRequest::KeyPassphrase { key_info })?;
    let pass_str = std::str::from_utf8(&pass)
        .map_err(|_| Error::Sign("passphrase must be UTF-8".into()))?;
    let sig = sign_detached_with_key(key_data, data, pass_str)?;
    Ok((sig, SignBackend::Software))
}

/// Testable core of [`sign_detached`] that accepts injected card-path
/// outcomes. Exists so CI (which has no hardware) can exercise the
/// card→software fallback logic.
///
/// `card_attempt`:
/// - `None`: no card matched (software-only flow).
/// - `Some(Ok(sig))`: card path succeeded, return `sig` with `Card` backend.
/// - `Some(Err(e))`: card path failed, fall back to software.
#[cfg(feature = "card")]
#[doc(hidden)]
pub fn sign_detached_inner<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    card_attempt: Option<Result<String>>,
    mut secret: F,
) -> Result<(String, SignBackend)>
where
    F: FnMut(SecretRequest<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>>,
{
    let card_err: Option<Error> = match card_attempt {
        Some(Ok(sig)) => return Ok((sig, SignBackend::Card)),
        Some(Err(e)) => {
            log::info!("card signing failed ({e}), falling back to software key");
            Some(e)
        }
        None => None,
    };

    if !key_info.is_secret {
        let msg = match card_err {
            Some(e) => format!(
                "no software secret key available for {} (card path failed: {e})",
                key_info.fingerprint
            ),
            None => format!("no secret key available for {}", key_info.fingerprint),
        };
        return Err(Error::Sign(msg));
    }

    let pass = secret(SecretRequest::KeyPassphrase { key_info })?;
    let pass_str = std::str::from_utf8(&pass)
        .map_err(|_| Error::Sign("passphrase must be UTF-8".into()))?;
    match sign_detached_with_key(key_data, data, pass_str) {
        Ok(sig) => Ok((sig, SignBackend::Software)),
        Err(sw_err) => match card_err {
            Some(c) => Err(Error::Sign(format!(
                "card signing failed: {c}; software fallback failed: {sw_err}"
            ))),
            None => Err(sw_err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, parse_key_bytes};

    #[test]
    fn sign_and_verify_software() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let sig = sign_detached_with_key(&key.secret_key, b"hello", "pw").unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));

        let info = parse_key_bytes(&key.secret_key, true).unwrap();
        assert!(info.is_secret);

        let verified = wecanencrypt::verify_bytes_detached(
            key.public_key.as_bytes(),
            b"hello",
            sig.as_bytes(),
        )
        .unwrap();
        assert!(verified);
    }

    #[test]
    fn sign_detached_uses_software_backend_without_card() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let (sig, backend) = sign_detached(
            &key.secret_key,
            &info,
            b"hello",
            |req| match req {
                SecretRequest::KeyPassphrase { .. } => {
                    Ok(zeroize::Zeroizing::new(b"pw".to_vec()))
                }
                SecretRequest::CardPin { .. } => {
                    panic!("no card, should not request PIN")
                }
            },
        )
        .unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));
        assert_eq!(backend, SignBackend::Software);
    }

    #[cfg(feature = "card")]
    #[test]
    fn card_failure_falls_back_to_software() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        // Simulate: card was found and attempted, but card signing failed
        // (e.g. wrong PIN). The software path must still succeed.
        let card_attempt = Some(Err::<String, _>(Error::Card("wrong PIN".into())));
        let (sig, backend) = sign_detached_inner(
            &key.secret_key,
            &info,
            b"hello",
            card_attempt,
            |req| match req {
                SecretRequest::KeyPassphrase { .. } => {
                    Ok(zeroize::Zeroizing::new(b"pw".to_vec()))
                }
                SecretRequest::CardPin { .. } => {
                    panic!("card_attempt already consumed; should not be re-requested")
                }
            },
        )
        .unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));
        assert_eq!(backend, SignBackend::Software);
    }

    #[cfg(feature = "card")]
    #[test]
    fn card_failure_and_software_failure_report_both() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let card_attempt = Some(Err::<String, _>(Error::Card("wrong PIN".into())));
        // Software path fails because passphrase is wrong.
        let err = sign_detached_inner(
            &key.secret_key,
            &info,
            b"hello",
            card_attempt,
            |_| Ok(zeroize::Zeroizing::new(b"bad-passphrase".to_vec())),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("card signing failed"));
        assert!(msg.contains("software fallback failed"));
    }

    #[cfg(feature = "card")]
    #[test]
    fn card_failure_no_secret_reports_card_error() {
        let alice = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
        // Strip the secret to simulate a public-only key in the store.
        let info = parse_key_bytes(alice.public_key.as_bytes(), true).unwrap();
        assert!(!info.is_secret);

        let card_attempt = Some(Err::<String, _>(Error::Card("wrong PIN".into())));
        let err = sign_detached_inner(
            alice.public_key.as_bytes(),
            &info,
            b"hello",
            card_attempt,
            |_| panic!("should not request any secret when key is public-only"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no software secret key available"));
        assert!(msg.contains("card path failed"));
    }
}
