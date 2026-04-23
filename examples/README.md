# libtumpa examples

Small throwaway binaries that exercise libtumpa against real hardware
or generate test material. None of them are shipped to crates.io — the
`examples/` directory is excluded from the `include = [...]` list in
`Cargo.toml`.

Build with the `card` feature so the PC/SC backend is compiled in:

```
cargo run --example <NAME> --features card
```

| Example | Hardware required | Destructive | Purpose |
|---|---|---|---|
| `nitrokey_probe` | Any OpenPGP card | No | Enumerate connected cards and check whether any is a Nitrokey (manufacturer `000F`). |
| `nitrokey_guard_check` | Real Nitrokey | No | End-to-end proof that `libtumpa::card::upload::upload` rejects a `Cv25519` legacy key on a Nitrokey **before** any reset/write. Safe to run on a provisioned card. |
| `emit_cv25519_key` | None | No | Prints a binary `Cv25519` (legacy) secret key to stdout. Used to generate test material for downstream CLIs that need to exercise the Nitrokey rejection path. |

## `nitrokey_probe`

Read-only enumeration via `list_all_cards` + `get_card_details`.
Prints one line per card and flags which one(s) are Nitrokeys.

```
$ cargo run --example nitrokey_probe --features card
connected cards: 2
  ident=0000:00000001  manufacturer_name=Testcard
    manufacturer=0000  manufacturer_name=Testcard  is_nitrokey=false
  ident=000F:CB9A5355  manufacturer_name=Nitrokey GmbH
    manufacturer=000F  manufacturer_name=Nitrokey GmbH  is_nitrokey=true

✓ Nitrokey detected — guard would fire on incompatible algorithms
```

## `nitrokey_guard_check`

Feeds a freshly generated `Cv25519` (legacy) cert into
`libtumpa::card::upload::upload` against the attached Nitrokey and
asserts that `Error::CardUnsupportedAlgorithm` fires **before**
`reset_card` runs. Exits 0 on the expected guard error, exits 2 if
the upload succeeds (which would mean the guard regressed and your
card may have been wiped).

```
$ cargo run --example nitrokey_guard_check --features card
using Nitrokey ident=000F:CB9A5355
✓ guard fired before any destructive op: card="Nitrokey GmbH" rejected algorithm="EdDSALegacy"
```

Safe to run on a provisioned card — the guard runs before any APDU
that touches card state.

## `emit_cv25519_key`

Generates a `Cv25519` (legacy, EdDSALegacy + ECDH/Curve25519) secret
key with passphrase `"pw"` and UID `"Alice <alice@example.com>"`, and
writes the binary OpenPGP bytes to stdout. No hardware, no
destination — pipe it wherever you need test material.

```
$ cargo run --example emit_cv25519_key --features card > /tmp/cv25519.key
```

### How we used it during the tumpa-cli migration

When migrating `tumpa-cli` to libtumpa 0.2.0, we needed to prove that
the `tcli --upload-to-card` command surfaces libtumpa's Nitrokey guard
correctly end-to-end — i.e. that a user feeding a Cv25519 key hits
the `"Nitrokey GmbH does not support EdDSALegacy"` error **before**
the card is reset. That needed an actual Cv25519 secret key in a
tumpa keystore; there is no `tcli generate` subcommand, so we
produced the material out-of-band.

The full sequence:

```bash
# 1. Generate a throwaway Cv25519 secret key.
cd libtumpa
cargo run --example emit_cv25519_key --features card > /tmp/cv25519.key

# 2. Import it into a scratch keystore (not the user's real one).
cd ../tumpa-cli
TUMPA_KEYSTORE=/tmp/tcli_test.db \
  cargo run --bin tcli -- --import /tmp/cv25519.key
# => Imported 8531BAF3...D93D9769 (Alice <alice@example.com>)

# 3. Sanity-check: confirm it's actually EdDSA (Cv25519 legacy).
TUMPA_KEYSTORE=/tmp/tcli_test.db \
  cargo run --bin tcli -- --info 8531BAF3...D93D9769
# => sec  8531...  EdDSA256  [certify]
# =>     Subkeys: ECDH256 [encryption], EdDSA256 [signing], EdDSA256 [authentication]

# 4. Try to upload to the Nitrokey with TUMPA_PASSPHRASE=pw for
#    non-interactive passphrase entry.
TUMPA_KEYSTORE=/tmp/tcli_test.db TUMPA_PASSPHRASE=pw \
  cargo run --features experimental --bin tcli -- \
    --upload-to-card 8531BAF3...D93D9769 \
    --which sub \
    --card-ident 000F:CB9A5355
```

Expected output:

```
Warning: --upload-to-card factory-resets the card first ...
Press Ctrl-C within 3 seconds to abort.
Error: failed to upload signing subkey of 8531BAF3...D93D9769 to card: \
       Nitrokey GmbH does not support EdDSALegacy
```

The guard fired, the Nitrokey was not touched, and the error message
wraps cleanly through anyhow's context layer. That single run
validates the full chain: libtumpa classifier → libtumpa guard →
tumpa-cli anyhow wrapping → user-visible message.

### Cleanup

`emit_cv25519_key` writes to stdout only. Remove the scratch files
afterwards:

```bash
rm -f /tmp/cv25519.key /tmp/tcli_test.db
```
