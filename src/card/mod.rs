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

pub use wecanencrypt::card::{
    find_cards_for_key, get_card_details, is_card_connected, list_all_cards, reset_card,
    CardInfo, CardKeyMatch, CardSummary, KeySlot, TouchMode,
};
pub use wecanencrypt::card::{
    decrypt_bytes_on_card, sign_bytes_detached_on_card,
};

use crate::error::{Error, Result};

/// Which key slot to target during upload / admin / expiry operations.
pub use wecanencrypt::card::upload::CardKeySlot;

pub(crate) fn require_card_connected() -> Result<()> {
    if !is_card_connected() {
        return Err(Error::CardNotConnected);
    }
    Ok(())
}
