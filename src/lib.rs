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
//! needs a secret borrows it (`&str` for a passphrase, `&[u8]` for a
//! card PIN) and never copies it. It is the caller's job to keep that
//! secret in a zeroing container and drop it promptly.
//!
//! The recommended pattern is:
//!
//! ```no_run
//! use zeroize::Zeroizing;
//! # use libtumpa::{key, KeyStore};
//! # fn demo(store: &KeyStore, fp: &str) -> libtumpa::Result<()> {
//! let password = Zeroizing::new(String::from("my-passphrase"));
//! let info = key::add_uid(store, fp, "Alice <a@example.com>", &password)?;
//! // `password`'s backing buffer is zeroed when it drops here.
//! # let _ = info;
//! # Ok(())
//! # }
//! ```
//!
//! For card PINs use `Zeroizing<Vec<u8>>`:
//!
//! ```no_run
//! # #[cfg(feature = "card")]
//! # {
//! use zeroize::Zeroizing;
//! use libtumpa::card::admin;
//! let admin_pin: Zeroizing<Vec<u8>> = Zeroizing::new(b"12345678".to_vec());
//! admin::set_cardholder_name("Alice", &admin_pin, None).ok();
//! # }
//! ```
//!
//! **Warning:** passing a bare `String` or `Vec<u8>` compiles fine but
//! leaves the secret in process memory until the value is dropped or
//! reallocated. Frontends that receive secrets from IPC (e.g. Tauri
//! commands that deserialize a JSON body into `String`) **must** wrap
//! the value in `Zeroizing` at the entry point, before calling into
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
