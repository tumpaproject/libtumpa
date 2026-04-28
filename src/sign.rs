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

use wecanencrypt::{HashAlgorithm, KeyInfo};

use crate::error::{Error, Result};
use crate::store;
use crate::{Passphrase, Pin};

/// Parse a tclig / GnuPG-style digest-algo name into a `HashAlgorithm`.
///
/// Accepts SHA256/SHA384/SHA512 (case-insensitive, optional `-` separator).
/// SHA1 / MD5 / RIPEMD-160 are deliberately rejected — they're outside
/// what RFC 9580 §9.5 considers acceptable for new signatures and we
/// don't want a `--digest-algo SHA1` flag to silently downgrade email
/// signatures.
pub fn parse_digest_algo(s: &str) -> Result<HashAlgorithm> {
    let normalized: String = s
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' '))
        .flat_map(|c| c.to_uppercase())
        .collect();
    match normalized.as_str() {
        "SHA256" | "SHA2256" => Ok(HashAlgorithm::Sha256),
        "SHA384" | "SHA2384" => Ok(HashAlgorithm::Sha384),
        "SHA512" | "SHA2512" => Ok(HashAlgorithm::Sha512),
        _ => Err(Error::InvalidInput(format!(
            "unsupported digest algorithm '{s}'; \
             accepted values: SHA256, SHA384, SHA512"
        ))),
    }
}

/// Sign `data` with a software secret key, producing an armored detached
/// signature.
pub fn sign_detached_with_key(
    key_data: &[u8],
    data: &[u8],
    passphrase: &Passphrase,
) -> Result<String> {
    if passphrase.is_empty() {
        // wecanencrypt will error, but catch it early for a clearer message.
        return Err(Error::Sign("empty passphrase".into()));
    }
    wecanencrypt::sign_bytes_detached(key_data, data, passphrase.as_str())
        .map_err(|e| Error::Sign(format!("sign_bytes_detached: {e}")))
}

/// Sign `data` with a software secret key, optionally pinning the hash
/// algorithm. Returns the armored signature plus the hash algorithm
/// actually used — needed for callers that have to fill the
/// `multipart/signed` `micalg` parameter (RFC 3156).
pub fn sign_detached_with_key_and_hash(
    key_data: &[u8],
    data: &[u8],
    passphrase: &Passphrase,
    hash_algo: Option<HashAlgorithm>,
) -> Result<wecanencrypt::DetachedSignOutput> {
    if passphrase.is_empty() {
        return Err(Error::Sign("empty passphrase".into()));
    }
    wecanencrypt::sign_bytes_detached_with_hash(key_data, data, passphrase.as_str(), hash_algo)
        .map_err(|e| Error::Sign(format!("sign_bytes_detached_with_hash: {e}")))
}

/// Sign `data` with a software secret key, producing a cleartext-signed
/// (`-----BEGIN PGP SIGNED MESSAGE-----`) message with the original text
/// embedded.
///
/// Cleartext signatures are text-only by definition; binary input may
/// roundtrip but is not the supported use case. There is no card-based
/// equivalent today — for card-only keys use [`sign_detached`].
pub fn sign_cleartext_with_key(
    key_data: &[u8],
    data: &[u8],
    passphrase: &Passphrase,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Sign("empty passphrase".into()));
    }
    wecanencrypt::sign_bytes_cleartext(key_data, data, passphrase.as_str())
        .map_err(|e| Error::Sign(format!("sign_bytes_cleartext: {e}")))
}

/// Convert an ASCII-armored detached signature (`-----BEGIN PGP
/// SIGNATURE-----` … `-----END PGP SIGNATURE-----`) to its binary
/// representation by round-tripping through `pgp::DetachedSignature`.
///
/// Used by callers that want a `.sig` (binary) output but have an armored
/// signature in hand because the underlying signer (software or card)
/// only emits armored output.
pub fn dearmor_detached_signature(armored: &[u8]) -> Result<Vec<u8>> {
    use pgp::composed::{Deserializable, DetachedSignature};
    use pgp::ser::Serialize;
    use std::io::Cursor;

    let (sig, _headers) = DetachedSignature::from_armor_single(Cursor::new(armored))
        .map_err(|e| Error::Sign(format!("dearmor: failed to parse armored signature: {e}")))?;
    let mut out = Vec::with_capacity(armored.len());
    sig.to_writer(&mut out).map_err(|e| {
        Error::Sign(format!(
            "dearmor: failed to serialize binary signature: {e}"
        ))
    })?;
    Ok(out)
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
    /// matching `key_data`. Pass `ident` to bind to a specific card when
    /// multiple cards are connected.
    pub fn sign_detached_on_card(
        key_data: &[u8],
        data: &[u8],
        pin: &Pin,
        ident: Option<&str>,
    ) -> Result<String> {
        wecanencrypt::card::sign_bytes_detached_on_card(data, key_data, pin.as_slice(), ident)
            .map_err(|e| Error::Card(format!("sign_bytes_detached_on_card: {e}")))
    }

    /// Sign `text` with a connected OpenPGP card, producing a cleartext-
    /// signed (`-----BEGIN PGP SIGNED MESSAGE-----`) message.
    ///
    /// Counterpart to [`super::sign_cleartext_with_key`] for card-backed
    /// keys. The card produces the signature; the wrapping armored
    /// CleartextSignedMessage is built in software.
    pub fn sign_cleartext_on_card(
        key_data: &[u8],
        data: &[u8],
        pin: &Pin,
        ident: Option<&str>,
    ) -> Result<Vec<u8>> {
        wecanencrypt::card::sign_text_cleartext_on_card(data, key_data, pin.as_slice(), ident)
            .map_err(|e| Error::Card(format!("sign_text_cleartext_on_card: {e}")))
    }
}

#[cfg(feature = "card")]
pub use card_signing::{find_signing_card, sign_cleartext_on_card, sign_detached_on_card};

/// Tell a caller which signing backend was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignBackend {
    Card,
    Software,
}

/// Result of [`sign_detached_with_hash`]: signature plus the metadata a
/// PGP/MIME `multipart/signed` builder needs (`micalg` parameter, signer
/// backend annotation).
#[derive(Debug, Clone)]
pub struct DetachedSignResult {
    pub armored: String,
    pub backend: SignBackend,
    pub hash_algorithm: HashAlgorithm,
}

/// Extract the hash algorithm field from an armored detached signature.
///
/// Used to surface the actual hash a card-backed signing produced
/// (the card chooses; we don't override). For software signing the
/// caller already knows the algorithm but we round-trip through this
/// helper anyway for symmetry.
#[allow(dead_code)]
fn hash_algorithm_of_armored_sig(armored: &[u8]) -> Result<HashAlgorithm> {
    use pgp::composed::{Deserializable, DetachedSignature};
    use std::io::Cursor;

    let (sig, _) = DetachedSignature::from_armor_single(Cursor::new(armored))
        .map_err(|e| Error::Sign(format!("could not re-parse own signature: {e}")))?;
    let cfg = sig.signature.config().ok_or_else(|| {
        Error::Sign("signature config missing — cannot determine hash algorithm".into())
    })?;
    Ok(cfg.hash_alg)
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

/// Secret returned by the `secret` closure in [`sign_detached`].
///
/// The variant must match the [`SecretRequest`] variant: a `CardPin`
/// request expects a [`Secret::Pin`], a `KeyPassphrase` request expects
/// a [`Secret::Passphrase`]. A mismatch returns [`Error::Sign`].
pub enum Secret {
    Pin(Pin),
    Passphrase(Passphrase),
}

#[cfg(feature = "card")]
impl Secret {
    fn into_pin(self) -> Result<Pin> {
        match self {
            Secret::Pin(p) => Ok(p),
            Secret::Passphrase(_) => Err(Error::Sign(
                "closure returned a passphrase, but a card PIN was requested".into(),
            )),
        }
    }
    fn into_passphrase(self) -> Result<Passphrase> {
        match self {
            Secret::Passphrase(p) => Ok(p),
            Secret::Pin(_) => Err(Error::Sign(
                "closure returned a PIN, but a key passphrase was requested".into(),
            )),
        }
    }
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
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    // A failure to contact the PCSC service (e.g. pcscd not running, no
    // reader drivers installed) means "no card visible", not "hard fail".
    // Log and fall through to the software path.
    let card_attempt: Option<Result<String>> = match find_signing_card(key_data) {
        Ok(Some(m)) => {
            let card_ident = m.card.ident.clone();
            Some(
                secret(SecretRequest::CardPin {
                    card_ident: &card_ident,
                    key_info,
                })
                .and_then(Secret::into_pin)
                .and_then(|pin| sign_detached_on_card(key_data, data, &pin, Some(&card_ident))),
            )
        }
        Ok(None) => None,
        Err(e) => {
            log::info!(
                "could not enumerate smartcards ({e}); skipping card path, using software key"
            );
            None
        }
    };

    sign_detached_inner(key_data, key_info, data, card_attempt, secret)
}

/// Like [`sign_detached`] but accepts a `hash_preference` and reports the
/// hash algorithm that was actually used.
///
/// **Card path** ignores `hash_preference`: smartcards pick the digest
/// from their slot's algorithm capabilities and we don't override. We
/// still round-trip through the resulting signature packet to surface the
/// actual hash via [`DetachedSignResult::hash_algorithm`] so PGP/MIME
/// callers can fill `micalg` correctly.
///
/// **Software path** honors `hash_preference` if `Some`; if `None`, the
/// hash is auto-selected from the signing key's public params.
#[cfg(feature = "card")]
pub fn sign_detached_with_hash<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    hash_preference: Option<HashAlgorithm>,
    mut secret: F,
) -> Result<DetachedSignResult>
where
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    let card_attempt: Option<Result<String>> = match find_signing_card(key_data) {
        Ok(Some(m)) => {
            let card_ident = m.card.ident.clone();
            Some(
                secret(SecretRequest::CardPin {
                    card_ident: &card_ident,
                    key_info,
                })
                .and_then(Secret::into_pin)
                .and_then(|pin| sign_detached_on_card(key_data, data, &pin, Some(&card_ident))),
            )
        }
        Ok(None) => None,
        Err(e) => {
            log::info!(
                "could not enumerate smartcards ({e}); skipping card path, using software key"
            );
            None
        }
    };

    if hash_preference.is_some() && card_attempt.as_ref().is_some_and(|r| r.is_ok()) {
        log::info!("hash preference ignored on card-backed sign; the card chose its own digest");
    }

    sign_detached_inner_with_hash(
        key_data,
        key_info,
        data,
        hash_preference,
        card_attempt,
        secret,
    )
}

/// Software-only [`sign_detached_with_hash`] variant (no card support).
#[cfg(not(feature = "card"))]
pub fn sign_detached_with_hash<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    hash_preference: Option<HashAlgorithm>,
    mut secret: F,
) -> Result<DetachedSignResult>
where
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    if !key_info.is_secret {
        return Err(Error::Sign(format!(
            "no secret key available for {}",
            key_info.fingerprint
        )));
    }
    let pass = match secret(SecretRequest::KeyPassphrase { key_info })? {
        Secret::Passphrase(p) => p,
        Secret::Pin(_) => {
            return Err(Error::Sign(
                "closure returned a PIN, but a key passphrase was requested".into(),
            ))
        }
    };
    let out =
        wecanencrypt::sign_bytes_detached_with_hash(key_data, data, pass.as_str(), hash_preference)
            .map_err(|e| Error::Sign(format!("sign_bytes_detached_with_hash: {e}")))?;
    Ok(DetachedSignResult {
        armored: out.armored,
        backend: SignBackend::Software,
        hash_algorithm: out.hash_algorithm,
    })
}

/// Sign `data` as a cleartext-signed message, trying a connected card
/// first and falling back to the software key.
///
/// Mirrors [`sign_detached`]: the caller's closure is invoked once for
/// [`SecretRequest::CardPin`] when a matching card is connected, and once
/// for [`SecretRequest::KeyPassphrase`] when falling back to a software
/// key. If the key has no software secret material **and** no matching
/// card, returns [`Error::Sign`].
///
/// Returns the cleartext-signed message bytes plus the backend that
/// produced the signature.
#[cfg(feature = "card")]
pub fn sign_cleartext<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    mut secret: F,
) -> Result<(Vec<u8>, SignBackend)>
where
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    let card_attempt: Option<Result<Vec<u8>>> = match find_signing_card(key_data) {
        Ok(Some(m)) => {
            let card_ident = m.card.ident.clone();
            Some(
                secret(SecretRequest::CardPin {
                    card_ident: &card_ident,
                    key_info,
                })
                .and_then(Secret::into_pin)
                .and_then(|pin| sign_cleartext_on_card(key_data, data, &pin, Some(&card_ident))),
            )
        }
        Ok(None) => None,
        Err(e) => {
            log::info!(
                "could not enumerate smartcards ({e}); skipping card path, using software key"
            );
            None
        }
    };

    let card_err: Option<Error> = match card_attempt {
        Some(Ok(signed)) => return Ok((signed, SignBackend::Card)),
        Some(Err(e)) => {
            log::info!("card cleartext signing failed ({e}), falling back to software key");
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
            None => format!(
                "inline (cleartext) signing requires a software secret key for {} \
                 and no matching card was found",
                key_info.fingerprint
            ),
        };
        return Err(Error::Sign(msg));
    }

    let pass = match secret(SecretRequest::KeyPassphrase { key_info })? {
        Secret::Passphrase(p) => p,
        Secret::Pin(_) => {
            return Err(Error::Sign(
                "closure returned a PIN, but a key passphrase was requested".into(),
            ))
        }
    };
    match sign_cleartext_with_key(key_data, data, &pass) {
        Ok(signed) => Ok((signed, SignBackend::Software)),
        Err(sw_err) => match card_err {
            Some(c) => Err(Error::Sign(format!(
                "card cleartext signing failed: {c}; software fallback failed: {sw_err}"
            ))),
            None => Err(sw_err),
        },
    }
}

/// Software-only [`sign_cleartext`] variant (no card support).
#[cfg(not(feature = "card"))]
pub fn sign_cleartext<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    mut secret: F,
) -> Result<(Vec<u8>, SignBackend)>
where
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    if !key_info.is_secret {
        return Err(Error::Sign(format!(
            "inline (cleartext) signing requires a software secret key for {}; \
             card-only keys are not supported (build without `card` feature) \
             — use detached signing instead",
            key_info.fingerprint
        )));
    }

    let pass = match secret(SecretRequest::KeyPassphrase { key_info })? {
        Secret::Passphrase(p) => p,
        Secret::Pin(_) => {
            return Err(Error::Sign(
                "closure returned a PIN, but a key passphrase was requested".into(),
            ))
        }
    };
    let signed = sign_cleartext_with_key(key_data, data, &pass)?;
    Ok((signed, SignBackend::Software))
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
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    store::ensure_key_usable_for_signing(key_info)?;

    if !key_info.is_secret {
        return Err(Error::Sign(format!(
            "no secret key available for {}",
            key_info.fingerprint
        )));
    }
    let pass = match secret(SecretRequest::KeyPassphrase { key_info })? {
        Secret::Passphrase(p) => p,
        Secret::Pin(_) => {
            return Err(Error::Sign(
                "closure returned a PIN, but a key passphrase was requested".into(),
            ))
        }
    };
    let sig = sign_detached_with_key(key_data, data, &pass)?;
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
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
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

    let pass = secret(SecretRequest::KeyPassphrase { key_info })?.into_passphrase()?;
    match sign_detached_with_key(key_data, data, &pass) {
        Ok(sig) => Ok((sig, SignBackend::Software)),
        Err(sw_err) => match card_err {
            Some(c) => Err(Error::Sign(format!(
                "card signing failed: {c}; software fallback failed: {sw_err}"
            ))),
            None => Err(sw_err),
        },
    }
}

/// Hash-aware variant of [`sign_detached_inner`]. Card path returns
/// whatever hash the card chose (parsed back out of the signature
/// packet); software path honors `hash_preference`.
#[cfg(feature = "card")]
#[doc(hidden)]
pub fn sign_detached_inner_with_hash<F>(
    key_data: &[u8],
    key_info: &KeyInfo,
    data: &[u8],
    hash_preference: Option<HashAlgorithm>,
    card_attempt: Option<Result<String>>,
    mut secret: F,
) -> Result<DetachedSignResult>
where
    F: FnMut(SecretRequest<'_>) -> Result<Secret>,
{
    let card_err: Option<Error> = match card_attempt {
        Some(Ok(sig)) => {
            let hash_algorithm = hash_algorithm_of_armored_sig(sig.as_bytes())?;
            return Ok(DetachedSignResult {
                armored: sig,
                backend: SignBackend::Card,
                hash_algorithm,
            });
        }
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

    let pass = secret(SecretRequest::KeyPassphrase { key_info })?.into_passphrase()?;
    match sign_detached_with_key_and_hash(key_data, data, &pass, hash_preference) {
        Ok(out) => Ok(DetachedSignResult {
            armored: out.armored,
            backend: SignBackend::Software,
            hash_algorithm: out.hash_algorithm,
        }),
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
    use chrono::{Duration, Utc};
    use wecanencrypt::{
        create_key, create_key_simple, parse_key_bytes, revoke_key, CipherSuite, SubkeyFlags,
    };

    fn pw(s: &str) -> Passphrase {
        Passphrase::new(s.to_string())
    }

    #[test]
    fn sign_and_verify_software() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let sig = sign_detached_with_key(&key.secret_key, b"hello", &pw("pw")).unwrap();
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

        let (sig, backend) = sign_detached(&key.secret_key, &info, b"hello", |req| match req {
            SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
            SecretRequest::CardPin { .. } => panic!("no card, should not request PIN"),
        })
        .unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));
        assert_eq!(backend, SignBackend::Software);
    }

    #[test]
    fn sign_detached_rejects_revoked_key() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&key.secret_key, "pw").unwrap();
        let info = parse_key_bytes(&revoked, true).unwrap();

        let err = sign_detached(&revoked, &info, b"hello", |_| {
            Ok(Secret::Passphrase(pw("pw")))
        })
        .unwrap_err();
        assert!(matches!(err, Error::UnusableKey { .. }));
    }

    #[test]
    fn sign_detached_rejects_expired_key() {
        let creation_time = Utc::now() - Duration::days(3);
        let expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            "pw",
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            Some(expiry),
            Some(expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let err = sign_detached(&key.secret_key, &info, b"hello", |_| {
            Ok(Secret::Passphrase(pw("pw")))
        })
        .unwrap_err();
        assert!(matches!(err, Error::UnusableKey { .. }));
    }

    #[cfg(feature = "card")]
    #[test]
    fn card_failure_falls_back_to_software() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let card_attempt = Some(Err::<String, _>(Error::Card("wrong PIN".into())));
        let (sig, backend) = sign_detached_inner(
            &key.secret_key,
            &info,
            b"hello",
            card_attempt,
            |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
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
        let err = sign_detached_inner(&key.secret_key, &info, b"hello", card_attempt, |_| {
            Ok(Secret::Passphrase(pw("bad-passphrase")))
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("card signing failed"));
        assert!(msg.contains("software fallback failed"));
    }

    #[cfg(feature = "card")]
    #[test]
    fn card_failure_no_secret_reports_card_error() {
        let alice = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
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

    #[cfg(feature = "card")]
    #[test]
    fn closure_returning_wrong_secret_type_errors() {
        let key = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        // No card attempt → software path. Closure returns a PIN instead
        // of a passphrase — must be rejected.
        let err = sign_detached_inner(&key.secret_key, &info, b"hello", None, |_| {
            Ok(Secret::Pin(Pin::new(b"12345678".to_vec())))
        })
        .unwrap_err();
        assert!(err.to_string().contains("PIN"));
    }

    /// PCSC unavailable (pcscd not running, no reader) must degrade to
    /// the software path, not hard-fail the sign. Regression guard for
    /// the tumpa-cli CI failure where `Failed to create a pcsc smartcard
    /// context` bubbled all the way out of tclig.
    #[cfg(feature = "card")]
    #[test]
    fn pcsc_error_falls_back_to_software() {
        let key = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        // Simulate the shape of the CI error: card_attempt is `None`
        // because the outer `sign_detached` converted the PCSC error
        // into "no card" via the new match arm. The software path
        // must still succeed with a good passphrase.
        let (sig, backend) =
            sign_detached_inner(&key.secret_key, &info, b"hello", None, |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
                SecretRequest::CardPin { .. } => {
                    panic!("card path should be skipped when PCSC is unavailable")
                }
            })
            .unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));
        assert_eq!(backend, SignBackend::Software);
    }

    #[test]
    fn cleartext_sign_and_verify_software() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let (signed, backend) =
            sign_cleartext(&key.secret_key, &info, b"hello\n", |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
                SecretRequest::CardPin { .. } => {
                    // No card connected on CI, so the closure is only
                    // invoked for KeyPassphrase. Defensive panic guards
                    // against a regression in the no-card path.
                    panic!("cleartext path must not request a PIN when no card is present")
                }
            })
            .unwrap();
        assert_eq!(backend, SignBackend::Software);

        let signed_str = std::str::from_utf8(&signed).unwrap();
        assert!(signed_str.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(signed_str.contains("hello"));
        assert!(signed_str.contains("-----BEGIN PGP SIGNATURE-----"));

        let verified = wecanencrypt::verify_bytes(key.public_key.as_bytes(), &signed).unwrap();
        assert!(verified);
    }

    #[test]
    fn cleartext_sign_rejects_public_only_key() {
        let key = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
        let info = parse_key_bytes(key.public_key.as_bytes(), true).unwrap();
        assert!(!info.is_secret);

        let err = sign_cleartext(key.public_key.as_bytes(), &info, b"hello", |_| {
            panic!("should reject before requesting any secret")
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("inline (cleartext) signing requires a software secret key"));
    }

    /// PCSC unavailable / no matching card on a host that has the `card`
    /// feature compiled in must still produce a software-backed cleartext
    /// signature when the keystore has the secret material. Mirrors
    /// `pcsc_error_falls_back_to_software` for the detached path.
    #[cfg(feature = "card")]
    #[test]
    fn cleartext_sign_falls_back_to_software_when_no_card() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        // No card connected on CI → `find_signing_card` returns `None`
        // and the closure is invoked once for `KeyPassphrase` only.
        let (signed, backend) =
            sign_cleartext(&key.secret_key, &info, b"hello\n", |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
                SecretRequest::CardPin { .. } => {
                    panic!("card path should be skipped when no card is connected")
                }
            })
            .unwrap();

        assert_eq!(backend, SignBackend::Software);
        let signed_str = std::str::from_utf8(&signed).unwrap();
        assert!(signed_str.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        let verified = wecanencrypt::verify_bytes(key.public_key.as_bytes(), &signed).unwrap();
        assert!(verified);
    }

    #[test]
    fn cleartext_sign_rejects_pin_secret() {
        let key = create_key_simple("pw", &["Alice <a@e.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let err = sign_cleartext(&key.secret_key, &info, b"hello", |_| {
            Ok(Secret::Pin(Pin::new(b"12345678".to_vec())))
        })
        .unwrap_err();
        assert!(err.to_string().contains("PIN"));
    }

    #[test]
    fn dearmor_roundtrips_to_verifiable_binary() {
        let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let armored = sign_detached_with_key(&key.secret_key, b"hello", &pw("pw")).unwrap();

        let binary = dearmor_detached_signature(armored.as_bytes()).unwrap();
        // Sanity: binary form is shorter than ASCII armor.
        assert!(binary.len() < armored.len());
        // First byte must be a packet header tag (high bit set per OpenPGP).
        assert!(
            !binary.is_empty() && (binary[0] & 0x80) != 0,
            "got first byte: {:#x}",
            binary[0]
        );

        // Verify the binary form is still a valid detached signature.
        let valid =
            wecanencrypt::verify_bytes_detached(key.public_key.as_bytes(), b"hello", &binary)
                .unwrap();
        assert!(valid);
    }

    #[test]
    fn dearmor_rejects_garbage() {
        let err = dearmor_detached_signature(b"not an armored signature").unwrap_err();
        assert!(err.to_string().contains("dearmor"));
    }

    #[test]
    fn parse_digest_algo_accepts_canonical_names() {
        assert_eq!(parse_digest_algo("SHA256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(parse_digest_algo("sha256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(parse_digest_algo("SHA-256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(
            parse_digest_algo("sha2-256").unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(parse_digest_algo("SHA384").unwrap(), HashAlgorithm::Sha384);
        assert_eq!(parse_digest_algo("SHA512").unwrap(), HashAlgorithm::Sha512);
    }

    #[test]
    fn parse_digest_algo_rejects_weak_and_unknown() {
        // Explicit reject of weak algos: GnuPG accepts them; we do not.
        for weak in ["SHA1", "MD5", "RIPEMD160", "RIPEMD-160"] {
            let err = parse_digest_algo(weak).unwrap_err();
            assert!(
                err.to_string().contains("unsupported"),
                "should reject {weak}: got {err}"
            );
        }
        // Garbage.
        assert!(parse_digest_algo("blake3").is_err());
        assert!(parse_digest_algo("").is_err());
    }

    #[test]
    fn sign_detached_with_hash_default_software() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let result =
            sign_detached_with_hash(&key.secret_key, &info, b"hello", None, |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
                SecretRequest::CardPin { .. } => panic!("no card"),
            })
            .unwrap();

        assert_eq!(result.backend, SignBackend::Software);
        assert_eq!(result.hash_algorithm, HashAlgorithm::Sha256);
        assert!(result.armored.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn sign_detached_with_hash_override_sha512() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();

        let result = sign_detached_with_hash(
            &key.secret_key,
            &info,
            b"hello",
            Some(HashAlgorithm::Sha512),
            |req| match req {
                SecretRequest::KeyPassphrase { .. } => Ok(Secret::Passphrase(pw("pw"))),
                SecretRequest::CardPin { .. } => panic!("no card"),
            },
        )
        .unwrap();

        assert_eq!(result.backend, SignBackend::Software);
        assert_eq!(result.hash_algorithm, HashAlgorithm::Sha512);

        // Sanity: the signature must still verify.
        let ok = wecanencrypt::verify_bytes_detached(
            key.public_key.as_bytes(),
            b"hello",
            result.armored.as_bytes(),
        )
        .unwrap();
        assert!(ok);
    }

    /// Round-trip through the same hash-extraction helper used by the
    /// card path. Guards against a future change that breaks armored
    /// re-parsing.
    #[test]
    fn hash_algorithm_extraction_round_trip() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let armored = sign_detached_with_key(&key.secret_key, b"x", &pw("pw")).unwrap();
        let alg = hash_algorithm_of_armored_sig(armored.as_bytes()).unwrap();
        assert_eq!(alg, HashAlgorithm::Sha256);
    }
}
