//! # libtumpa
//!
//! Shared high-level OpenPGP key, smartcard, and keystore operations used by
//! tumpa-cli and the tumpa desktop app. Built on top of the
//! [`wecanencrypt`] crate.
//!
//! libtumpa owns the code that was previously duplicated across tumpa-cli's
//! `store.rs`/`gpg/*` modules and tumpa's `src-tauri/commands/*`: key
//! resolution, usability checks, the high-level key lifecycle (generate,
//! import, export, UID add/revoke, expiry updates, password change,
//! revocation), smartcard operations (upload, admin, touch modes,
//! card↔key linking via `wecanencrypt.card_keys`), sign/verify/encrypt/
//! decrypt with card-first dispatch, and (optionally) WKD fetch + VKS
//! upload/verify.
//!
//! ## Design
//!
//! - No UI: passphrases and card PINs are always supplied by the caller.
//!   Pinentry/terminal/agent acquisition stays in tumpa-cli.
//! - Functional API: free functions that take `&KeyStore` and `&str` /
//!   `&[u8]` secret refs. See the next section for the required secret
//!   lifecycle.
//! - Types are re-exported from wecanencrypt where possible.
//!
//! ## Secret handling
//!
//! libtumpa **does not own** passphrases or PINs. Every function that
//! needs a secret takes `&Passphrase` or `&Pin` — both are type aliases
//! for `Zeroizing<...>`, so the caller cannot pass a bare `String` or
//! `Vec<u8>` by accident. The secret is borrowed for the duration of
//! the call and the caller's `Zeroizing` container zeroes its backing
//! memory on drop.
//!
//! ```no_run
//! # use libtumpa::{key, KeyStore, Passphrase};
//! # fn demo(store: &KeyStore, fp: &str) -> libtumpa::Result<()> {
//! let password = Passphrase::new(String::from("my-passphrase"));
//! let info = key::add_uid(store, fp, "Alice <a@example.com>", &password)?;
//! // `password`'s backing buffer is zeroed when it drops at end of scope.
//! # let _ = info;
//! # Ok(())
//! # }
//! ```
//!
//! For card PINs use [`Pin`]:
//!
//! ```no_run
//! # #[cfg(feature = "card")]
//! # {
//! use libtumpa::{card::admin, Pin};
//! let admin_pin = Pin::new(b"12345678".to_vec());
//! admin::set_cardholder_name("Alice", &admin_pin, None).ok();
//! # }
//! ```
//!
//! Frontends that receive secrets from IPC (e.g. Tauri commands that
//! deserialize a JSON body into `String`) should wrap the value in
//! [`Passphrase`] / [`Pin`] at the entry point, before calling into
//! libtumpa.
//!
//! ## Features
//!
//! - `card` (default) — smartcard ops
//! - `network` — WKD fetch + VKS upload (`libtumpa::network`)

pub mod cache;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod key;
pub mod paths;
pub mod sign;
pub mod store;
pub mod verify;

#[cfg(feature = "card")]
pub mod card;

#[cfg(feature = "network")]
pub mod network;

// Re-export wecanencrypt types most-used by consumers.
pub use wecanencrypt::{
    CipherSuite, GeneratedKey, KeyInfo, KeyStore, KeyType, SubkeyFlags, SubkeyInfo, UserIDInfo,
};

pub use error::{Error, Result};
pub use zeroize::Zeroizing;

/// A key passphrase.
///
/// Always a `Zeroizing<String>`: the backing UTF-8 buffer is overwritten
/// with zeros when the value drops. Every libtumpa API that needs a
/// passphrase takes `&Passphrase`, so the caller cannot accidentally pass
/// a plain `String` that would linger in memory.
///
/// ```
/// use libtumpa::Passphrase;
/// let pw: Passphrase = Passphrase::new("my-passphrase".into());
/// // ... use &pw ...
/// // `pw` zeroes on drop at end of scope.
/// ```
pub type Passphrase = Zeroizing<String>;

/// A smartcard PIN.
///
/// Always a `Zeroizing<Vec<u8>>`: the backing buffer is overwritten on
/// drop. libtumpa functions that accept a card PIN require `&Pin` to
/// force the caller into the zeroing container.
pub type Pin = Zeroizing<Vec<u8>>;
