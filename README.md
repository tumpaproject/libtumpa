# libtumpa

Shared tumpa library: high-level OpenPGP key, smartcard, and keystore
operations on top of [`wecanencrypt`].

libtumpa owns the code that was previously duplicated across
[`tumpa-cli`](https://github.com/tumpaproject/tumpa-cli)'s `store.rs` /
`gpg/*` modules and [`tumpa`](https://github.com/tumpaproject/tumpa)'s
`src-tauri/commands/*`: key resolution, usability checks, the
high-level key lifecycle (generate, import, export, UID add/revoke,
expiry updates, password change, revocation), smartcard operations
(upload, admin, touch modes, card↔key linking via
`wecanencrypt.card_keys`), sign/verify/encrypt/decrypt with card-first
dispatch, and (optionally) WKD fetch + VKS upload/verify.

## Design

- **No UI.** Passphrases and card PINs are always supplied by the
  caller. Pinentry/terminal/agent acquisition stays in tumpa-cli.
- **Secrets are always zeroing.** Every function that takes a
  passphrase or a PIN requires `&Passphrase` (= `&Zeroizing<String>`)
  or `&Pin` (= `&Zeroizing<Vec<u8>>`). Raw `&str` / `&[u8]` won't
  compile.
- **Functional API.** Free functions over `&KeyStore`. Types are
  re-exported from `wecanencrypt` where possible.
- **Deployment-owned keystore identity.** On Unix, `store::open_keystore`
  creates explicitly named parent directories and database files with private
  `0700`/`0600` modes, rejecting group/other access and symlinks on those
  paths. A database named directly in the current directory validates only the
  file, preserving the library's existing behavior. The library deliberately
  does not enforce a file-owning UID because the legitimate owner varies for
  service accounts, containers, and managed mounts. Applications with an
  ownership policy must validate it before opening the keystore.

## Features

- `card` (default) — smartcard operations via wecanencrypt's `card`
  feature.
- `network` — WKD fetch + keys.openpgp.org (VKS) upload / email
  verification.

## Quick start

```rust
use libtumpa::{key, store, KeyStore, Passphrase, SubkeyFlags};

let store = KeyStore::open_in_memory()?;
let pw = Passphrase::new("my-passphrase".into());

let info = key::generate_and_import(
    &store,
    key::GenerateKeyParams {
        uids: vec!["Alice <alice@example.com>".into()],
        subkey_flags: SubkeyFlags::all(),
        ..Default::default()
    },
    &pw,
)?;

let (key_data, _) = store.get_key(&info.fingerprint)?;
store::ensure_key_usable_for_signing(&info)?;
# Ok::<(), libtumpa::Error>(())
```

See the crate-level rustdoc for the full secret-handling contract and
the `sign::sign_detached` card-first / software-fallback closure API.

## License

GPL-3.0-or-later.

[`wecanencrypt`]: https://crates.io/crates/wecanencrypt
