//! Render a `tcli describe`-shaped multi-line summary of a key.
//!
//! Used by `tumpa-cli`'s `cmd_info` (which wraps this with `println!`)
//! and by the macOS Mail extension's "Key details" sheet (which calls
//! through `tumpa-uniffi`). Keeping the renderer here means the CLI and
//! the desktop UI cannot drift.
//!
//! The output shape is:
//!
//! ```text
//! pub  37417ABF...0537  Ed25519  [sign, certify]
//!      Created:  2024-09-12 09:00:00 UTC
//!      Expires:  never
//!      UIDs:
//!        [primary] Kushal Das <kushal@civilized.systems>
//!      Subkeys:
//!        AAAA...  Ed25519  [signing]
//!                 Created:  ...
//!                 Expires:  ...
//!      Cards:
//!        000F:CB9A5355  Nitrokey GmbH (CB9A5355)  [S E A]
//! ```
//!
//! The `Cards:` block is appended only when the keystore has linked
//! card rows for the fingerprint; callers that don't have a keystore
//! handle (e.g. `tcli describe <file>` parsing a raw cert) call
//! [`format_key_info`] directly and skip the cards footer.

use wecanencrypt::keystore::StoredCardKey;
use wecanencrypt::KeyInfo;

const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S UTC";

/// Render the body of `tcli describe` for one key.
///
/// `key_data` is the raw cert bytes (armored or binary) — needed because
/// `KeyInfo` does not carry the primary key's bit-length, and matching
/// `tcli describe` exactly requires it. Callers who already hold the
/// keystore-stored bytes pass them through; callers who only have a
/// `KeyInfo` can pass an empty slice (the primary algorithm prefix
/// degrades to empty in that case, mirroring the existing behavior).
pub fn format_key_info(key_data: &[u8], key_info: &KeyInfo) -> String {
    let mut out = String::with_capacity(512);

    let key_type = if key_info.is_secret { "sec" } else { "pub" };

    let primary_algo = wecanencrypt::get_key_cipher_details(key_data)
        .ok()
        .and_then(|details| details.into_iter().next())
        .map(|d| format_algo(&d.algorithm, d.bit_length))
        .unwrap_or_default();

    let mut primary_caps = Vec::new();
    if key_info.can_primary_sign {
        primary_caps.push("sign");
    }
    primary_caps.push("certify");

    out.push_str(&format!(
        "{}  {}  {}  [{}]\n",
        key_type,
        key_info.fingerprint,
        primary_algo,
        primary_caps.join(", ")
    ));
    out.push_str(&format!(
        "     Created:  {}\n",
        key_info.creation_time.format(TIME_FMT)
    ));
    if let Some(ref exp) = key_info.expiration_time {
        out.push_str(&format!("     Expires:  {}\n", exp.format(TIME_FMT)));
    } else {
        out.push_str("     Expires:  never\n");
    }

    if key_info.is_revoked {
        if let Some(ref rev) = key_info.revocation_time {
            out.push_str(&format!("     Revoked:  {}\n", rev.format(TIME_FMT)));
        } else {
            out.push_str("     Revoked:  yes\n");
        }
    }

    let mut uids: Vec<_> = key_info.user_ids.iter().filter(|u| !u.revoked).collect();
    uids.sort_by_key(|u| std::cmp::Reverse(u.is_primary));

    if !uids.is_empty() {
        out.push_str("     UIDs:\n");
        for uid in &uids {
            let prefix = if uid.is_primary {
                "[primary] "
            } else {
                "          "
            };
            out.push_str(&format!("       {}{}\n", prefix, uid.value));
        }
    }

    if !key_info.subkeys.is_empty() {
        out.push_str("     Subkeys:\n");
        for sk in &key_info.subkeys {
            let revoked = if sk.is_revoked { " [REVOKED]" } else { "" };
            let algo = format_algo(&sk.algorithm, sk.bit_length);
            out.push_str(&format!(
                "       {}  {}  [{}]{}\n",
                sk.fingerprint, algo, sk.key_type, revoked
            ));
            out.push_str(&format!(
                "                 Created:  {}\n",
                sk.creation_time.format(TIME_FMT)
            ));
            if let Some(t) = sk.expiration_time {
                out.push_str(&format!(
                    "                 Expires:  {}\n",
                    t.format(TIME_FMT)
                ));
            }
        }
    }

    out
}

/// Append the `Cards:` block produced by
/// [`crate::card::link::render_card_links_for_key`] to `body`.
///
/// No-op when `assocs` is empty (no linked cards → no footer).
///
/// Gated on the card features because `crate::card` only compiles
/// when `feature = "card"` or `feature = "card-mobile"` is enabled.
/// A `#[cfg(not(...))]` no-op shim with the same signature is
/// provided so callers don't need their own cfg chain — the only
/// way to obtain a non-empty `assocs` slice without the card
/// features is to construct one by hand, in which case the no-op
/// shim simply emits no Cards footer.
#[cfg(any(feature = "card", feature = "card-mobile"))]
pub fn append_card_links(body: &mut String, assocs: &[StoredCardKey]) {
    for line in crate::card::link::render_card_links_for_key(assocs) {
        body.push_str(&line);
        body.push('\n');
    }
}

#[cfg(not(any(feature = "card", feature = "card-mobile")))]
pub fn append_card_links(_body: &mut String, _assocs: &[StoredCardKey]) {}

fn format_algo(algorithm: &str, bit_length: usize) -> String {
    if bit_length > 0 {
        format!("{}{}", algorithm, bit_length)
    } else {
        algorithm.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "card", feature = "card-mobile"))]
    use wecanencrypt::KeyStore;
    use wecanencrypt::{create_key_simple, parse_key_bytes};

    fn alice() -> (Vec<u8>, KeyInfo) {
        let gen = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let bytes = gen.public_key.into_bytes();
        let info = parse_key_bytes(&bytes, false).unwrap();
        (bytes, info)
    }

    #[test]
    fn header_line_marks_pub_for_public_only_cert() {
        let (bytes, info) = alice();
        let out = format_key_info(&bytes, &info);
        let first = out.lines().next().unwrap();
        assert!(first.starts_with("pub  "), "got: {first}");
        assert!(first.contains(&info.fingerprint));
        // `certify` is always present on the primary; `sign` only when
        // the primary itself carries the signing flag (typical certs
        // delegate signing to a subkey).
        assert!(first.contains("certify"), "got: {first}");
        let expected_caps = if info.can_primary_sign {
            "[sign, certify]"
        } else {
            "[certify]"
        };
        assert!(first.contains(expected_caps), "got: {first}");
    }

    #[test]
    fn primary_uid_marked_and_first() {
        let (bytes, info) = alice();
        let out = format_key_info(&bytes, &info);
        let uid_line = out
            .lines()
            .find(|l| l.contains("Alice <alice@example.com>"))
            .expect("uid present");
        assert!(uid_line.contains("[primary]"), "got: {uid_line}");
    }

    #[test]
    fn subkeys_block_lists_each_subkey_with_created_line() {
        let (bytes, info) = alice();
        let out = format_key_info(&bytes, &info);
        assert!(out.contains("Subkeys:"));
        for sk in &info.subkeys {
            assert!(
                out.contains(&sk.fingerprint),
                "subkey {} missing in:\n{out}",
                sk.fingerprint
            );
        }
        // One Created: line per subkey + one for the primary.
        let created_count = out.matches("Created:").count();
        assert_eq!(created_count, 1 + info.subkeys.len());
    }

    #[test]
    fn never_expiring_key_renders_expires_never() {
        let (bytes, info) = alice();
        let out = format_key_info(&bytes, &info);
        assert!(out.contains("Expires:  never"));
    }

    #[test]
    fn append_card_links_is_noop_when_no_associations() {
        let (bytes, info) = alice();
        let mut s = format_key_info(&bytes, &info);
        let before = s.clone();
        append_card_links(&mut s, &[]);
        assert_eq!(s, before);
    }

    #[cfg(any(feature = "card", feature = "card-mobile"))]
    #[test]
    fn append_card_links_appends_renderer_output() {
        let (bytes, info) = alice();
        let mut s = format_key_info(&bytes, &info);

        let assoc = StoredCardKey {
            card_ident: "000F:CB9A5355".into(),
            card_serial: "CB9A5355".into(),
            card_manufacturer: Some("Nitrokey GmbH".into()),
            slot: "signature".into(),
            slot_fingerprint: "AAAA".into(),
            last_seen: "2026-04-29T00:00:00Z".into(),
        };
        append_card_links(&mut s, std::slice::from_ref(&assoc));

        assert!(s.ends_with('\n'));
        assert!(s.contains("Cards:"));
        assert!(s.contains("000F:CB9A5355"));
        assert!(s.contains("Nitrokey GmbH (CB9A5355)"));
        assert!(s.contains("[S]"));
    }

    #[cfg(any(feature = "card", feature = "card-mobile"))]
    #[test]
    fn end_to_end_through_keystore_links_card() {
        // Round-trip: import a generated cert into a keystore, link a
        // card to it, and verify the rendered describe output ends in
        // the expected "Cards:" block. Pins the integration we ship
        // for the Mail extension's key-detail sheet.
        let store = KeyStore::open_in_memory().unwrap();
        let gen = create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        let fp = store.import_key(&gen.secret_key).unwrap();
        store
            .save_card_key(
                &fp,
                "000F:CB9A5355",
                "CB9A5355",
                Some("Nitrokey GmbH"),
                "signature",
                "AAAA",
            )
            .unwrap();

        let (bytes, info) = crate::store::resolve_signer(&store, &fp).unwrap();
        let assocs = crate::card::link::card_associations(&store, &fp).unwrap();

        let mut s = format_key_info(&bytes, &info);
        append_card_links(&mut s, &assocs);

        assert!(
            s.starts_with("sec  "),
            "secret key in keystore → 'sec' header"
        );
        assert!(s.contains("Bob <bob@example.com>"));
        assert!(s.contains("Cards:"));
        assert!(s.contains("000F:CB9A5355"));
    }
}
