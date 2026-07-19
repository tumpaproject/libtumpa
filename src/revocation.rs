//! Shared signer-revocation policy for verification paths.

use wecanencrypt::KeyInfo;

/// Match signature issuer identifiers to one OpenPGP key.
///
/// `issuer_ids` may contain a full fingerprint, a key ID, or both, as extracted
/// from a signature's issuer subpackets. Matching is exact: abbreviated or
/// suffix-only identifiers are not accepted. OpenPGP hex identifiers are
/// ASCII, so case-insensitive comparison avoids allocating normalized copies
/// while accepting either encoded case.
///
/// This comparison is shared by cryptographic key selection and revocation
/// policy so both paths interpret signature issuer identifiers identically.
pub(crate) fn issuer_matches_key(issuer_ids: &[String], fingerprint: &str, key_id: &str) -> bool {
    issuer_ids
        .iter()
        .any(|id| id.eq_ignore_ascii_case(fingerprint) || id.eq_ignore_ascii_case(key_id))
}

/// Determine whether a resolved signer is revoked for a specific signature.
///
/// Primary-certificate revocation invalidates every signature from the
/// certificate. A subkey revocation invalidates only signatures whose issuer
/// identifiers match that exact subkey's fingerprint or key ID. Consequently,
/// a revoked unrelated subkey does not invalidate a signature made by another
/// still-usable key on the same certificate.
pub(crate) fn signer_is_revoked(cert_info: &KeyInfo, issuer_ids: &[String]) -> bool {
    // A primary-key revocation applies to the certificate as a whole, so no
    // issuer-level matching is necessary in this case.
    if cert_info.is_revoked {
        return true;
    }

    // Do not let revocation of an encryption or authentication subkey poison
    // a valid signature made by a different signing subkey.
    cert_info.subkeys.iter().any(|subkey| {
        subkey.is_revoked && issuer_matches_key(issuer_ids, &subkey.fingerprint, &subkey.key_id)
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Cursor;

    use pgp::composed::{Deserializable, SignedSecretKey, SignedSecretSubKey};
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails as _, KeyVersion, Password, Timestamp};
    use rand::thread_rng;

    /// Parse an armored or binary transferable secret key used by a test.
    ///
    /// # Panics
    ///
    /// Panics when `bytes` is not a valid transferable OpenPGP secret key.
    pub(crate) fn parse_secret_key(bytes: &[u8]) -> SignedSecretKey {
        SignedSecretKey::from_armor_single(Cursor::new(bytes))
            .or_else(|_| SignedSecretKey::from_bytes(bytes).map(|key| (key, Default::default())))
            .map(|(key, _)| key)
            .expect("parse test secret key")
    }

    /// Append a genuine primary-key-issued revocation to one secret subkey.
    ///
    /// The resulting transferable secret key is serialized and imported via
    /// the public keystore API, exercising real revocation parsing rather than
    /// mutating cached [`KeyInfo`](wecanencrypt::KeyInfo) metadata in memory.
    /// Existing binding signatures and all non-target subkeys are preserved.
    ///
    /// # Panics
    ///
    /// Panics if `target_index` is out of bounds, the primary key cannot be
    /// unlocked with `password`, or the revocation cannot be serialized.
    pub(crate) fn revoke_subkey(
        key: &SignedSecretKey,
        password: &str,
        target_index: usize,
    ) -> Vec<u8> {
        let target = &key.secret_subkeys[target_index];

        // Bind the revocation cryptographically to this certificate's primary
        // key and identify that issuer in standard signature subpackets.
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &key.primary_key,
            SignatureType::SubkeyRevocation,
        )
        .expect("create subkey revocation config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                .expect("encode revocation creation time"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                key.primary_key.fingerprint(),
            ))
            .expect("encode revocation issuer fingerprint"),
        ];
        if key.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                key.primary_key.legacy_key_id(),
            ))
            .expect("encode revocation issuer key ID")];
        }

        // Subkey revocations sign the public forms of the primary and subkey.
        let revocation = config
            .sign_subkey_binding(
                &key.primary_key,
                key.primary_key.public_key(),
                &Password::from(password),
                target.key.public_key(),
            )
            .expect("sign subkey revocation");

        // Preserve the original binding signatures and append the revocation
        // to the selected subkey's packet sequence.
        let mut subkeys = key.secret_subkeys.clone();
        let revoked = &mut subkeys[target_index];
        let mut signatures = revoked.signatures.clone();
        signatures.push(revocation);
        *revoked = SignedSecretSubKey::new(revoked.key.clone(), signatures);

        SignedSecretKey::new(
            key.primary_key.clone(),
            key.details.clone(),
            key.public_subkeys.clone(),
            subkeys,
        )
        .to_bytes()
        .expect("serialize key with revoked signing subkey")
    }
}
