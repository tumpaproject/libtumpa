//! Card↔key linking, persisted in the keystore's `card_keys` table.
//!
//! Consolidates what `tumpa` previously stored in `~/.tumpa/card_links.json`.
//! The JSON file is intentionally **not** migrated here — the tumpa desktop
//! `card_links.json` code never shipped, so new builds simply resync.

#[cfg(feature = "card")]
use wecanencrypt::card::{get_card_details, list_all_cards};
use wecanencrypt::card::{CardInfo, CardSummary, KeySlot};
use wecanencrypt::keystore::StoredCardKey;
use wecanencrypt::KeyStore;

use crate::error::{Error, Result};

/// A candidate match between a key in the keystore and a connected card.
#[derive(Debug, Clone)]
pub struct CardKeyDetection {
    pub key_fingerprint: String,
    pub card_ident: String,
    pub card_summary: CardSummary,
    pub slot: KeySlot,
    pub slot_fingerprint: String,
}

/// Return the card idents currently linked to this key.
pub fn card_idents_for_key(store: &KeyStore, key_fingerprint: &str) -> Result<Vec<String>> {
    let stored = store
        .get_card_keys(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("get_card_keys: {e}")))?;
    let mut idents: Vec<String> = stored.into_iter().map(|c| c.card_ident).collect();
    idents.sort();
    idents.dedup();
    Ok(idents)
}

/// Return a fingerprint → deduped card idents map for every key in
/// the store, using one SQL query instead of one-per-key.
///
/// Equivalent to calling [`card_idents_for_key`] for every
/// fingerprint returned by `KeyStore::list_fingerprints`, but
/// collapsed into a single round trip. Intended for list-view callers
/// (e.g. the desktop key list) that need card associations for every
/// key at once; the per-key variant stays for detail-screen callers.
///
/// Per-fingerprint idents are sorted and deduplicated to match the
/// shape of [`card_idents_for_key`].
pub fn card_idents_map(store: &KeyStore) -> Result<std::collections::HashMap<String, Vec<String>>> {
    let all = store
        .list_all_card_keys()
        .map_err(|e| Error::KeyStore(format!("list_all_card_keys: {e}")))?;
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (fingerprint, card) in all {
        map.entry(fingerprint).or_default().push(card.card_ident);
    }
    for idents in map.values_mut() {
        idents.sort();
        idents.dedup();
    }
    Ok(map)
}

/// Return the full `card_keys` rows for this key (slot + slot fingerprint).
pub fn card_associations(store: &KeyStore, key_fingerprint: &str) -> Result<Vec<StoredCardKey>> {
    store
        .get_card_keys(key_fingerprint)
        .map_err(|e| Error::KeyStore(format!("get_card_keys: {e}")))
}

/// Record a single `(key, card, slot)` association.
///
/// `slot` should be `"signature"`, `"encryption"`, or `"authentication"`.
pub fn link(
    store: &KeyStore,
    key_fingerprint: &str,
    card_info: &CardInfo,
    slot: &str,
    slot_fingerprint: &str,
) -> Result<()> {
    store
        .save_card_key(
            key_fingerprint,
            &card_info.ident,
            &card_info.serial_number,
            card_info.manufacturer_name.as_deref(),
            slot,
            slot_fingerprint,
        )
        .map_err(|e| Error::KeyStore(format!("save_card_key: {e}")))
}

/// Remove all `card_keys` rows for a given card ident (across all keys).
pub fn unlink_card(store: &KeyStore, card_ident: &str) -> Result<()> {
    store
        .remove_card_keys_for_card(card_ident)
        .map_err(|e| Error::KeyStore(format!("remove_card_keys_for_card: {e}")))
}

/// Link every slot on `card_info` whose fingerprint matches a key (primary or
/// subkey) in the keystore.
///
/// This replaces tumpa's "auto-link after upload" logic.
pub fn auto_link_after_upload(
    store: &KeyStore,
    card_info: &CardInfo,
    key_fingerprint: &str,
) -> Result<()> {
    let slots: [(Option<&String>, &str); 3] = [
        (card_info.signature_fingerprint.as_ref(), "signature"),
        (card_info.encryption_fingerprint.as_ref(), "encryption"),
        (
            card_info.authentication_fingerprint.as_ref(),
            "authentication",
        ),
    ];

    for (fp_opt, slot_name) in slots {
        if let Some(slot_fp) = fp_opt {
            link(store, key_fingerprint, card_info, slot_name, slot_fp)?;
        }
    }
    Ok(())
}

/// Scan every connected card and report matches against the keystore.
///
/// **PCSC-only.** Enumeration is a desktop concept; on mobile each
/// card session is established explicitly via the UI, so auto-detect
/// across multiple cards doesn't apply.
///
/// A match is any slot whose fingerprint equals a primary- or subkey
/// fingerprint of a stored key (case-insensitive comparison, since card
/// fingerprints are typically lowercase while the keystore uses uppercase).
#[cfg(feature = "card")]
pub fn auto_detect(store: &KeyStore) -> Result<Vec<CardKeyDetection>> {
    let cards = list_all_cards().map_err(|e| Error::Card(e.to_string()))?;
    if cards.is_empty() {
        return Ok(Vec::new());
    }

    let certs = store
        .list_keys()
        .map_err(|e| Error::KeyStore(format!("list_keys: {e}")))?;
    if certs.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    for card in &cards {
        let info = match get_card_details(Some(&card.ident)) {
            Ok(i) => i,
            Err(_) => continue,
        };

        for (slot, slot_fp_opt) in [
            (KeySlot::Signature, info.signature_fingerprint.as_ref()),
            (KeySlot::Encryption, info.encryption_fingerprint.as_ref()),
            (
                KeySlot::Authentication,
                info.authentication_fingerprint.as_ref(),
            ),
        ] {
            let Some(slot_fp) = slot_fp_opt else {
                continue;
            };
            let slot_fp_upper = slot_fp.to_uppercase();

            for cert in &certs {
                let primary_match = cert.fingerprint.eq_ignore_ascii_case(&slot_fp_upper);
                let subkey_match = cert
                    .subkeys
                    .iter()
                    .any(|sk| sk.fingerprint.eq_ignore_ascii_case(&slot_fp_upper));
                if primary_match || subkey_match {
                    results.push(CardKeyDetection {
                        key_fingerprint: cert.fingerprint.clone(),
                        card_ident: card.ident.clone(),
                        card_summary: card.clone(),
                        slot,
                        slot_fingerprint: slot_fp.clone(),
                    });
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, KeyStore};

    fn dummy_card_info() -> CardInfo {
        CardInfo {
            ident: "TEST:0001".into(),
            serial_number: "0001".into(),
            cardholder_name: None,
            public_key_url: None,
            pin_retry_counter: 3,
            reset_code_retry_counter: 3,
            admin_pin_retry_counter: 3,
            signature_fingerprint: Some("AAAA".into()),
            encryption_fingerprint: Some("BBBB".into()),
            authentication_fingerprint: Some("CCCC".into()),
            manufacturer: None,
            manufacturer_name: Some("TestCo".into()),
            signature_counter: 0,
        }
    }

    #[test]
    fn link_unlink_roundtrip() {
        let store = KeyStore::open_in_memory().unwrap();
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let fp = store.import_key(&alice.secret_key).unwrap();

        let card = dummy_card_info();
        link(&store, &fp, &card, "signature", "AAAA").unwrap();
        let idents = card_idents_for_key(&store, &fp).unwrap();
        assert_eq!(idents, vec![card.ident.clone()]);

        unlink_card(&store, &card.ident).unwrap();
        assert!(card_idents_for_key(&store, &fp).unwrap().is_empty());
    }

    /// `card_idents_map` must produce exactly the same output as
    /// calling `card_idents_for_key` for every fingerprint in the
    /// store, just in one SQL query instead of N.
    #[test]
    fn card_idents_map_matches_per_key() {
        let store = KeyStore::open_in_memory().unwrap();

        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("pw", &["Bob <b@example.com>"]).unwrap();
        let fp_a = store.import_key(&alice.secret_key).unwrap();
        let fp_b = store.import_key(&bob.secret_key).unwrap();

        // Link Alice to two slots on one card AND a second card; link
        // Bob to one slot on a different card. The map must dedup
        // Alice's two-slots-same-card into a single ident.
        let card_a1 = CardInfo {
            ident: "FOO:1111".into(),
            ..dummy_card_info()
        };
        let card_a2 = CardInfo {
            ident: "FOO:2222".into(),
            serial_number: "2222".into(),
            ..dummy_card_info()
        };
        let card_b = CardInfo {
            ident: "BAR:3333".into(),
            serial_number: "3333".into(),
            ..dummy_card_info()
        };
        link(&store, &fp_a, &card_a1, "signature", "SIGA").unwrap();
        link(&store, &fp_a, &card_a1, "encryption", "ENCA").unwrap();
        link(&store, &fp_a, &card_a2, "signature", "SIGA2").unwrap();
        link(&store, &fp_b, &card_b, "signature", "SIGB").unwrap();

        // Per-key reference.
        let expected_a = card_idents_for_key(&store, &fp_a).unwrap();
        let expected_b = card_idents_for_key(&store, &fp_b).unwrap();
        assert_eq!(expected_a.len(), 2, "two-slots-same-card deduped to 1");
        assert_eq!(expected_b.len(), 1);

        let map = card_idents_map(&store).unwrap();
        assert_eq!(map.get(&fp_a).cloned().unwrap_or_default(), expected_a);
        assert_eq!(map.get(&fp_b).cloned().unwrap_or_default(), expected_b);
        assert_eq!(map.len(), 2);

        // Keys with no cards must simply be absent from the map, not
        // present with an empty Vec.
        let carol = create_key_simple("pw", &["Carol <c@example.com>"]).unwrap();
        let fp_c = store.import_key(&carol.secret_key).unwrap();
        let map2 = card_idents_map(&store).unwrap();
        assert!(!map2.contains_key(&fp_c));
    }
}
