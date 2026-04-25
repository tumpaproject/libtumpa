//! Card administration: PINs, cardholder name, URL, touch modes.

use wecanencrypt::card::{
    change_admin_pin as we_change_admin_pin, change_user_pin as we_change_user_pin,
    get_touch_modes as we_get_touch_modes, set_cardholder_name as we_set_name,
    set_public_key_url as we_set_url, set_touch_mode as we_set_touch, KeySlot, TouchMode,
};

use super::require_safe_implicit_card_target;
use crate::error::{Error, Result};
use crate::Pin;

/// Minimum length of a user PIN on most OpenPGP cards.
pub const USER_PIN_MIN_LEN: usize = 6;
/// Minimum length of an admin PIN on most OpenPGP cards.
pub const ADMIN_PIN_MIN_LEN: usize = 8;

/// Set the cardholder name (ISO 7816-6). Requires the admin PIN.
///
/// `ident` selects which card to target. When `None`, libtumpa requires
/// that exactly one card be connected — calling a card operation with
/// `ident = None` while multiple cards are plugged in is rejected
/// rather than silently targeting whichever card the PCSC layer picks
/// up first. Pass the card ident explicitly when multiple cards are
/// present.
pub fn set_cardholder_name(name: &str, admin_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    we_set_name(name, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}

/// Set the URL of the public key on the card. Requires the admin PIN.
///
/// `ident` selects which card to target; see [`set_cardholder_name`] for
/// multi-card semantics.
pub fn set_public_key_url(url: &str, admin_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    we_set_url(url, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}

/// Change the user PIN, proving authorization with the admin PIN.
///
/// (The underlying card command verifies the admin PIN and sets a new user
/// PIN in one shot; tumpa's UI exposes it as "change user PIN using admin".)
///
/// `ident` selects which card to target; see [`set_cardholder_name`] for
/// multi-card semantics.
pub fn change_user_pin(admin_pin: &Pin, new_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    if new_pin.len() < USER_PIN_MIN_LEN {
        return Err(Error::InvalidInput(format!(
            "user PIN must be at least {USER_PIN_MIN_LEN} characters"
        )));
    }
    we_change_user_pin(admin_pin.as_slice(), new_pin.as_slice(), ident)
        .map_err(|e| Error::Card(e.to_string()))
}

/// Change the admin PIN. Requires the current admin PIN.
///
/// `ident` selects which card to target; see [`set_cardholder_name`] for
/// multi-card semantics.
pub fn change_admin_pin(current_pin: &Pin, new_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    if new_pin.len() < ADMIN_PIN_MIN_LEN {
        return Err(Error::InvalidInput(format!(
            "admin PIN must be at least {ADMIN_PIN_MIN_LEN} characters"
        )));
    }
    we_change_admin_pin(current_pin.as_slice(), new_pin.as_slice(), ident)
        .map_err(|e| Error::Card(e.to_string()))
}

/// Touch mode for a single key slot.
#[derive(Debug, Clone)]
pub struct SlotTouchMode {
    pub slot: KeySlot,
    pub mode: Option<TouchMode>,
}

/// Return the current touch modes for the signing / encryption / authentication
/// slots. `None` for a slot means the card does not support touch policies there.
///
/// `ident` selects which card to target; see [`set_cardholder_name`] for
/// multi-card semantics.
pub fn get_touch_modes(ident: Option<&str>) -> Result<Vec<SlotTouchMode>> {
    require_safe_implicit_card_target(ident)?;
    let (sig, enc, auth) = we_get_touch_modes(ident).map_err(|e| Error::Card(e.to_string()))?;
    Ok(vec![
        SlotTouchMode {
            slot: KeySlot::Signature,
            mode: sig,
        },
        SlotTouchMode {
            slot: KeySlot::Encryption,
            mode: enc,
        },
        SlotTouchMode {
            slot: KeySlot::Authentication,
            mode: auth,
        },
    ])
}

/// Set the touch mode for a slot. Requires the admin PIN.
///
/// `ident` selects which card to target; see [`set_cardholder_name`] for
/// multi-card semantics.
pub fn set_touch_mode(
    slot: KeySlot,
    mode: TouchMode,
    admin_pin: &Pin,
    ident: Option<&str>,
) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    we_set_touch(slot, mode, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}

/// Factory-reset the connected OpenPGP card.
///
/// `TERMINATE DF` on an OpenPGP card requires the admin PIN to be in
/// the blocked state (retry counter == 0). This helper exhausts the
/// admin-PIN retry counter with wrong-PIN verifies first, then issues
/// the factory reset. After the reset the card is back to defaults:
/// user PIN `123456`, admin PIN `12345678`, all key slots empty.
///
/// `ident` selects which card to target; see [`set_cardholder_name`]
/// for multi-card semantics. Because this op is destructive, calling
/// with `ident = None` while multiple cards are connected is rejected
/// rather than silently targeting the first enumerated reader.
pub fn factory_reset_card(ident: Option<&str>) -> Result<()> {
    require_safe_implicit_card_target(ident)?;
    block_admin_pin(ident)?;
    wecanencrypt::card::reset_card(ident).map_err(|e| Error::Card(e.to_string()))
}

/// Drive the admin-PIN retry counter to zero so [`factory_reset_card`]'s
/// `TERMINATE DF` is accepted.
///
/// Reads the live counter from the card and loops until it hits `0`,
/// rather than hard-coding a particular retry limit -- some cards ship
/// with a non-3 default and an admin can configure their own. If a
/// wrong-PIN candidate happens to match the real admin PIN, the
/// counter won't decrement on that verify; the loop notices the
/// no-op and rotates to a different candidate. With four obviously
/// wrong candidates the chance of every one of them coinciding with
/// the real admin PIN is negligible.
fn block_admin_pin(ident: Option<&str>) -> Result<()> {
    // PIN values to cycle through if a verify fails to consume a retry.
    // Each is 8 bytes (the OpenPGP-card admin PIN minimum length).
    const CANDIDATES: &[&[u8]] = &[b"00000000", b"99999999", b"01234567", b"abcdefgh"];

    let mut retries = read_admin_retries(ident)?;
    if retries == 0 {
        return Ok(());
    }

    let mut candidate_idx = 0usize;
    let mut stuck_rotations = 0usize;
    while retries > 0 {
        let pin = CANDIDATES[candidate_idx % CANDIDATES.len()];
        // We don't act on `Ok(true)` here -- the counter is the ground
        // truth -- but we hold onto any `Err` from the verify so a
        // transport / APDU failure can be surfaced if the loop later
        // gives up, instead of being silently swallowed.
        let last_verify_err: Option<String> = wecanencrypt::card::verify_admin_pin(pin, ident)
            .err()
            .map(|e| e.to_string());

        let new_retries = read_admin_retries(ident)?;
        if new_retries >= retries {
            // No retry consumed -- this candidate matched the real
            // admin PIN, or the card refused the attempt without
            // decrementing. Rotate to a different candidate.
            candidate_idx += 1;
            stuck_rotations += 1;
            if stuck_rotations >= CANDIDATES.len() {
                let trailer = last_verify_err
                    .as_deref()
                    .map(|e| format!("; last verify error: {e}"))
                    .unwrap_or_default();
                return Err(Error::Card(format!(
                    "could not block admin PIN: retry counter stuck at {new_retries} \
                     after rotating through {} known-wrong PIN candidates{trailer}",
                    CANDIDATES.len()
                )));
            }
        } else {
            stuck_rotations = 0;
        }
        retries = new_retries;
    }
    Ok(())
}

fn read_admin_retries(ident: Option<&str>) -> Result<u8> {
    let (_user, _reset, admin) = wecanencrypt::card::get_pin_retry_counters(ident)
        .map_err(|e| Error::Card(e.to_string()))?;
    Ok(admin)
}
