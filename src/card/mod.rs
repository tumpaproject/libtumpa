//! Smartcard operations.
//!
//! Wraps `wecanencrypt::card` with tumpa-specific conveniences: bitmask-
//! driven upload, card↔key linking persisted in the keystore's `card_keys`
//! table, high-level expiry updates that also touch the keystore.
//!
//! Ported from `tumpa/src-tauri/src/commands/card.rs`.

pub mod admin;
pub mod expiry;
pub mod link;
pub mod upload;

pub use wecanencrypt::card::{decrypt_bytes_on_card, sign_bytes_detached_on_card};
pub use wecanencrypt::card::{
    find_cards_for_key, get_card_details, is_card_connected, list_all_cards, reset_card, CardInfo,
    CardKeyMatch, CardSummary, KeySlot, TouchMode,
};

use crate::error::{Error, Result};

/// Which key slot to target during upload / admin / expiry operations.
pub use wecanencrypt::card::upload::CardKeySlot;

/// Assert that the card we are about to operate on is unambiguous:
///
/// - At least one OpenPGP card must be connected.
/// - If `expected_ident` is `Some`, that specific card must be among the
///   connected cards.
/// - If `expected_ident` is `None`, there must be exactly one card
///   connected. Calling a card operation with `ident = None` while
///   multiple cards are plugged in is rejected rather than silently
///   targeting whichever card `wecanencrypt::card` happens to pick up
///   first; this matters for destructive operations (admin PIN change,
///   card reset, key upload) where writing to the wrong card can leak
///   credentials or wipe a user's key material.
pub(crate) fn require_safe_implicit_card_target(expected_ident: Option<&str>) -> Result<()> {
    let cards = list_all_cards().map_err(|e| Error::Card(e.to_string()))?;
    if cards.is_empty() {
        return Err(Error::CardNotConnected);
    }

    if let Some(expected_ident) = expected_ident {
        if !cards.iter().any(|card| card.ident == expected_ident) {
            return Err(Error::Card(format!(
                "card {expected_ident} is not connected"
            )));
        }
    }

    if cards.len() > 1 {
        let connected = cards
            .iter()
            .map(|card| card.ident.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Error::Card(format!(
            "multiple cards connected ({connected}); disconnect all but one before upload or expiry operations"
        )));
    }

    Ok(())
}
