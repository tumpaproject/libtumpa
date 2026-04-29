//! Card↔key linking, persisted in the keystore's `card_keys` table.
//!
//! Consolidates what `tumpa` previously stored in `~/.tumpa/card_links.json`.
//! The JSON file is intentionally **not** migrated here — the tumpa desktop
//! `card_links.json` code never shipped, so new builds simply resync.

#[cfg(feature = "card")]
use std::collections::hash_map::Entry;
#[cfg(feature = "card")]
use std::collections::HashMap;

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

/// Map a [`KeySlot`] to the textual name [`link`] expects.
///
/// The `card_keys.slot` column is documented as one of these three
/// strings; downstream consumers (the tumpa-cli SSH agent, the
/// proposed ops socket dispatcher) filter on `slot = "authentication"`
/// to find SSH-eligible cards, so any drift here silently breaks
/// ssh-add / git ssh-signing.
pub fn slot_str(slot: KeySlot) -> &'static str {
    match slot {
        KeySlot::Signature => "signature",
        KeySlot::Encryption => "encryption",
        KeySlot::Authentication => "authentication",
    }
}

/// Canonical print order for slot labels: signature, encryption,
/// authentication. Matches `tcli card status` output and the OpenPGP
/// card data-object order so consumer-facing renders stay consistent
/// with everything else the user sees.
pub fn slot_rank(slot: &str) -> u8 {
    match slot {
        "signature" => 0,
        "encryption" => 1,
        "authentication" => 2,
        _ => 99,
    }
}

/// Single-letter slot tag used in the `[S E A]` summary on
/// `tcli describe` and intended to be reused by other UIs (mail
/// extension status, future Tauri detail screens).
pub fn slot_tag(slot: &str) -> &'static str {
    match slot {
        "signature" => "S",
        "encryption" => "E",
        "authentication" => "A",
        _ => "?",
    }
}

/// Sort slot strings into the order `render_card_links_for_key`
/// emits them: by [`slot_rank`] first, then lexicographically.
///
/// The lexicographic tie-break only matters when two or more slot
/// strings share rank 99 (any future / unknown slot kind written by
/// a newer wecanencrypt). Without it, those rows would render in
/// HashMap-insertion order and produce nondeterministic output --
/// breaks reproducible-output tests and confuses `diff` consumers.
fn sort_slots_canonically(slots: &mut [String]) {
    slots.sort_by(|a, b| slot_rank(a).cmp(&slot_rank(b)).then_with(|| a.cmp(b)));
}

/// Render the "Cards holding this key" footer that `tcli describe`
/// appends after the subkey table.
///
/// Returns an empty Vec when `assocs` is empty (callers shouldn't
/// print a header in that case). One key may live on multiple cards
/// (e.g. signing on YubiKey, auth on Nitrokey, or the same key
/// replicated across two backups), so cards are grouped per
/// `card_ident` and the slot tags compressed into a single bracketed
/// list per card.
///
/// The 5-space leading gutter matches `tcli`'s `print_key_info` label
/// indentation. Other UIs that want a different gutter can either
/// trim the leading spaces or compose their own renderer using
/// [`slot_rank`] / [`slot_tag`] directly.
pub fn render_card_links_for_key(assocs: &[StoredCardKey]) -> Vec<String> {
    if assocs.is_empty() {
        return Vec::new();
    }

    // Group by card_ident, preserving the manufacturer/serial of the
    // first row seen for each card (these are identical across rows
    // for the same ident — the same card row gets the same metadata
    // every time `auto_link_after_upload` writes it).
    let mut by_card: std::collections::BTreeMap<String, (Option<String>, String, Vec<String>)> =
        std::collections::BTreeMap::new();
    for a in assocs {
        let entry = by_card.entry(a.card_ident.clone()).or_insert_with(|| {
            (
                a.card_manufacturer.clone(),
                a.card_serial.clone(),
                Vec::new(),
            )
        });
        if !entry.2.contains(&a.slot) {
            entry.2.push(a.slot.clone());
        }
    }

    let mut out = Vec::with_capacity(by_card.len() + 1);
    out.push("     Cards:".to_string());
    for (ident, (mfg, serial, mut slots)) in by_card {
        sort_slots_canonically(&mut slots);
        let tags = slots
            .iter()
            .map(|s| slot_tag(s))
            .collect::<Vec<_>>()
            .join(" ");
        let mfg_str = mfg.as_deref().unwrap_or("Unknown");
        out.push(format!(
            "       {}  {} ({})  [{}]",
            ident, mfg_str, serial, tags
        ));
    }
    out
}

/// Trim an [`auto_detect`] result to the requested card.
///
/// `None` passes everything through unchanged. `Some(ident)` keeps
/// only detections whose `card_ident` matches exactly. Pure: no I/O,
/// no PCSC, safe to call without `feature = "card"`.
pub fn filter_detections_by_card(
    detections: Vec<CardKeyDetection>,
    filter_card_ident: Option<&str>,
) -> Vec<CardKeyDetection> {
    let Some(ident) = filter_card_ident else {
        return detections;
    };
    detections
        .into_iter()
        .filter(|d| d.card_ident == ident)
        .collect()
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

/// Write every detection in `detections` to the keystore.
///
/// `link::link` wants `&CardInfo`; [`auto_detect`] only attaches the
/// lighter `CardSummary`, so we re-fetch `CardInfo` once per unique
/// `card_ident` (typically one PCSC round-trip per card in practice)
/// and reuse it across all that card's detections. Idempotent:
/// `save_card_key` is `INSERT OR REPLACE`, so re-applying the same
/// detection list rewrites the same rows.
///
/// **PCSC-only.** Mobile callers that already hold a `CardInfo` for
/// the connected card should call [`auto_link_after_upload`] or
/// [`link`] directly instead.
#[cfg(feature = "card")]
pub fn apply_detections(store: &KeyStore, detections: &[CardKeyDetection]) -> Result<()> {
    let mut info_cache: HashMap<String, CardInfo> = HashMap::new();
    for d in detections {
        // Single hash lookup per iteration via the Entry API. The
        // straight `or_insert(...)` form would eagerly evaluate
        // `get_card_details(...)` even on cache hits, hammering PCSC
        // once per detection -- defeats the whole point of the cache.
        // The match keeps the call lazy and lets `?` propagate the
        // error.
        let info = match info_cache.entry(d.card_ident.clone()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                let info = get_card_details(Some(&d.card_ident))
                    .map_err(|e| Error::Card(format!("get_card_details({}): {e}", d.card_ident)))?;
                v.insert(info)
            }
        };
        link(
            store,
            &d.key_fingerprint,
            info,
            slot_str(d.slot),
            &d.slot_fingerprint,
        )?;
    }
    Ok(())
}

/// Auto-detect every connected card↔keystore match and write it.
///
/// Convenience for callers that don't need a confirm-before-write
/// step. Equivalent to [`auto_detect`] followed by
/// [`apply_detections`]; returns the list of detections that were
/// written so callers can show "wrote N links" / list each row.
///
/// CLI flows that want a `--dry-run` should call [`auto_detect`] +
/// [`apply_detections`] separately so they can branch between the
/// two.
///
/// **PCSC-only.**
#[cfg(feature = "card")]
pub fn auto_link_all(store: &KeyStore) -> Result<Vec<CardKeyDetection>> {
    let detections = auto_detect(store)?;
    apply_detections(store, &detections)?;
    Ok(detections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::{create_key_simple, KeyStore};

    fn assoc(card_ident: &str, mfg: Option<&str>, serial: &str, slot: &str) -> StoredCardKey {
        StoredCardKey {
            card_ident: card_ident.to_string(),
            card_serial: serial.to_string(),
            card_manufacturer: mfg.map(str::to_string),
            slot: slot.to_string(),
            slot_fingerprint: format!("SLOTFP:{card_ident}:{slot}"),
            last_seen: "2026-04-29T00:00:00Z".to_string(),
        }
    }

    fn detection(card_ident: &str, slot: KeySlot, key_fp: &str) -> CardKeyDetection {
        CardKeyDetection {
            key_fingerprint: key_fp.to_string(),
            card_ident: card_ident.to_string(),
            card_summary: CardSummary {
                ident: card_ident.to_string(),
                manufacturer_name: "Test".to_string(),
                serial_number: card_ident
                    .split(':')
                    .nth(1)
                    .unwrap_or(card_ident)
                    .to_string(),
                cardholder_name: None,
            },
            slot,
            slot_fingerprint: format!("SLOTFP:{key_fp}"),
        }
    }

    // ---- slot_str / slot_rank / slot_tag ----

    #[test]
    fn slot_str_maps_every_variant() {
        assert_eq!(slot_str(KeySlot::Signature), "signature");
        assert_eq!(slot_str(KeySlot::Encryption), "encryption");
        assert_eq!(slot_str(KeySlot::Authentication), "authentication");
    }

    #[test]
    fn slot_rank_orders_canonically() {
        // Sig < Enc < Auth — matches `tcli card status` and OpenPGP
        // data-object order.
        assert!(slot_rank("signature") < slot_rank("encryption"));
        assert!(slot_rank("encryption") < slot_rank("authentication"));
    }

    #[test]
    fn slot_tag_one_letter_per_known_slot() {
        assert_eq!(slot_tag("signature"), "S");
        assert_eq!(slot_tag("encryption"), "E");
        assert_eq!(slot_tag("authentication"), "A");
        // Unknown / future slots fall back to "?" rather than
        // crashing — defensive for forward-compat with new slot
        // strings the keystore might persist.
        assert_eq!(slot_tag("attestation"), "?");
    }

    /// Two unknown slot strings share rank 99, so sort_by_key alone
    /// would leave their relative order up to the underlying sort's
    /// stability (which `sort_by_key` does NOT guarantee). The
    /// secondary lexicographic tie-break makes render output
    /// deterministic across runs.
    #[test]
    fn sort_slots_canonically_uses_lexicographic_tiebreaker_for_unknowns() {
        let mut xs = vec![
            "zeta".to_string(),
            "alpha".to_string(),
            "encryption".to_string(),
            "signature".to_string(),
            "mu".to_string(),
        ];
        sort_slots_canonically(&mut xs);
        assert_eq!(
            xs,
            vec![
                "signature".to_string(),  // rank 0
                "encryption".to_string(), // rank 1
                // three unknowns at rank 99 sorted alphabetically:
                "alpha".to_string(),
                "mu".to_string(),
                "zeta".to_string(),
            ]
        );
    }

    // ---- render_card_links_for_key ----

    #[test]
    fn render_empty_assocs_returns_empty() {
        assert!(render_card_links_for_key(&[]).is_empty());
    }

    #[test]
    fn render_single_card_single_slot() {
        let xs = vec![assoc(
            "000F:CB9A5355",
            Some("Nitrokey GmbH"),
            "CB9A5355",
            "authentication",
        )];
        let out = render_card_links_for_key(&xs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "     Cards:");
        assert_eq!(
            out[1],
            "       000F:CB9A5355  Nitrokey GmbH (CB9A5355)  [A]"
        );
    }

    #[test]
    fn render_single_card_three_slots_sorted_canonical() {
        // Input order is reversed; output must be S, E, A.
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "encryption",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "signature",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        assert_eq!(
            out[1],
            "       000F:CB9A5355  Nitrokey GmbH (CB9A5355)  [S E A]"
        );
    }

    /// Pins the multi-card case: one cert may live on multiple cards
    /// (signing on YubiKey + auth on Nitrokey, or the same key on a
    /// backup card). Render must emit one line per `card_ident`,
    /// grouping all that card's slots into a single tag list.
    #[test]
    fn render_multiple_cards_grouped_by_ident() {
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc("0006:00000001", Some("Yubico"), "00000001", "signature"),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "encryption",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        // header + 2 card lines (BTreeMap orders by card_ident
        // string, so 0006:* sorts before 000F:*).
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], "     Cards:");
        assert!(
            out[1].contains("0006:00000001") && out[1].ends_with("[S]"),
            "got: {}",
            out[1]
        );
        assert!(
            out[2].contains("000F:CB9A5355") && out[2].ends_with("[E A]"),
            "got: {}",
            out[2]
        );
    }

    #[test]
    fn render_unknown_manufacturer_falls_back() {
        let xs = vec![assoc("FFFF:DEADBEEF", None, "DEADBEEF", "signature")];
        let out = render_card_links_for_key(&xs);
        assert_eq!(out[1], "       FFFF:DEADBEEF  Unknown (DEADBEEF)  [S]");
    }

    #[test]
    fn render_dedupes_duplicate_slot_rows_per_card() {
        // Defensive: if two rows ever share (card_ident, slot) the
        // tag list still has each letter once.
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        assert!(out[1].ends_with("[A]"), "got: {}", out[1]);
        assert!(!out[1].contains("[A A]"));
    }

    // ---- filter_detections_by_card ----

    #[test]
    fn filter_none_passes_everything_through() {
        let xs = vec![
            detection("000F:AAA", KeySlot::Authentication, "FP1"),
            detection("0006:BBB", KeySlot::Signature, "FP2"),
        ];
        let out = filter_detections_by_card(xs, None);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn filter_matches_card_ident_exactly() {
        let xs = vec![
            detection("000F:AAA", KeySlot::Authentication, "FP1"),
            detection("0006:BBB", KeySlot::Signature, "FP2"),
            detection("000F:AAA", KeySlot::Encryption, "FP3"),
        ];
        let out = filter_detections_by_card(xs, Some("000F:AAA"));
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|d| d.card_ident == "000F:AAA"));
    }

    #[test]
    fn filter_returns_empty_when_no_card_matches() {
        let xs = vec![detection("000F:AAA", KeySlot::Authentication, "FP1")];
        let out = filter_detections_by_card(xs, Some("DEAD:BEEF"));
        assert!(out.is_empty());
    }

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
