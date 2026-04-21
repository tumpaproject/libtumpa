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
#[cfg(feature = "card-mobile")]
pub mod mobile;
pub mod upload;

/// Re-export of `wecanencrypt::card::external` so mobile consumers
/// (e.g. tumpa's `card_bridge` module) can register a backend
/// provider without taking a direct dep on wecanencrypt.
#[cfg(feature = "card-mobile")]
pub use wecanencrypt::card::external;

/// Re-export of the wecanencrypt error types needed inside a provider
/// closure registered via `external::set_backend_provider`. The
/// callback signature requires `wecanencrypt::error::Error` as the
/// error type, and that's not one of the types libtumpa otherwise
/// surfaces, so we make it accessible here specifically for mobile.
#[cfg(feature = "card-mobile")]
pub use wecanencrypt::card::CardError as WecanencryptCardError;
#[cfg(feature = "card-mobile")]
pub use wecanencrypt::Error as WecanencryptError;

pub use wecanencrypt::card::{
    decrypt_bytes_on_card, get_card_details, reset_card, sign_bytes_detached_on_card, CardInfo,
    CardKeyMatch, CardSummary, KeySlot, TouchMode,
};

// Card enumeration is PCSC-only. Under `card-mobile` the mobile UI
// establishes a single session explicitly via the tauri plugin, so
// these aren't needed.
#[cfg(feature = "card")]
pub use wecanencrypt::card::{find_cards_for_key, is_card_connected, list_all_cards};

#[allow(unused_imports)]
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
#[cfg(feature = "card")]
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

/// Mobile variant of [`require_safe_implicit_card_target`]. Always
/// succeeds — mobile transports (NFC / USB) only expose one active
/// card session at a time, so the multi-card ambiguity this check
/// guards against on desktop can't arise. The backend provider in
/// `wecanencrypt::card::external` is responsible for rejecting a
/// mismatched `ident` if one is provided.
#[cfg(all(feature = "card-mobile", not(feature = "card")))]
pub(crate) fn require_safe_implicit_card_target(_expected_ident: Option<&str>) -> Result<()> {
    Ok(())
}
