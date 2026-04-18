//! Card administration: PINs, cardholder name, URL, touch modes.

use wecanencrypt::card::{
    change_admin_pin as we_change_admin_pin, change_user_pin as we_change_user_pin,
    get_touch_modes as we_get_touch_modes, set_cardholder_name as we_set_name,
    set_public_key_url as we_set_url, set_touch_mode as we_set_touch, KeySlot, TouchMode,
};

use super::require_card_connected;
use crate::error::{Error, Result};
use crate::Pin;

/// Minimum length of a user PIN on most OpenPGP cards.
pub const USER_PIN_MIN_LEN: usize = 6;
/// Minimum length of an admin PIN on most OpenPGP cards.
pub const ADMIN_PIN_MIN_LEN: usize = 8;

/// Set the cardholder name (ISO 7816-6). Requires the admin PIN.
pub fn set_cardholder_name(name: &str, admin_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_card_connected()?;
    we_set_name(name, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}

/// Set the URL of the public key on the card. Requires the admin PIN.
pub fn set_public_key_url(url: &str, admin_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_card_connected()?;
    we_set_url(url, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}

/// Change the user PIN, proving authorization with the admin PIN.
///
/// (The underlying card command verifies the admin PIN and sets a new user
/// PIN in one shot; tumpa's UI exposes it as "change user PIN using admin".)
pub fn change_user_pin(admin_pin: &Pin, new_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_card_connected()?;
    if new_pin.len() < USER_PIN_MIN_LEN {
        return Err(Error::InvalidInput(format!(
            "user PIN must be at least {USER_PIN_MIN_LEN} characters"
        )));
    }
    we_change_user_pin(admin_pin.as_slice(), new_pin.as_slice(), ident)
        .map_err(|e| Error::Card(e.to_string()))
}

/// Change the admin PIN. Requires the current admin PIN.
pub fn change_admin_pin(current_pin: &Pin, new_pin: &Pin, ident: Option<&str>) -> Result<()> {
    require_card_connected()?;
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
pub fn get_touch_modes(ident: Option<&str>) -> Result<Vec<SlotTouchMode>> {
    require_card_connected()?;
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
pub fn set_touch_mode(
    slot: KeySlot,
    mode: TouchMode,
    admin_pin: &Pin,
    ident: Option<&str>,
) -> Result<()> {
    require_card_connected()?;
    we_set_touch(slot, mode, admin_pin.as_slice(), ident).map_err(|e| Error::Card(e.to_string()))
}
