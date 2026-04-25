# ADR 0001 — ECC card-import public-key prefix fix belongs in wecanencrypt, not in openpgp-card

- Status: accepted
- Date: 2026-04-24
- Deciders: Kushal Das
- Relates to: [openpgp-card#128](https://codeberg.org/openpgp-card/openpgp-card/issues/128)

## Context

Uploading a V4 `Cv25519Modern` secret key (Ed25519 Certify+Sign primary
+ X25519 encryption subkey + Ed25519 authentication subkey, fixture
`tests/files/v4_x25519_cs_primary.asc`, passphrase
`"redhat"`) to a Nitrokey 3 Mini (opcard-rs firmware ≥1.5) via
`libtumpa::card::upload::upload` failed on the first slot with:

```
Smart card error: Communication error: Key import failed:
OpenPGP card error status: Incorrect parameters in the command data field
```

i.e. the card returned `SW 6A80` on the import APDU. The YubiKey 5
accepted the same call. Example reproducer:
[`libtumpa/examples/upload_v4_x25519_cs.rs`](../../examples/upload_v4_x25519_cs.rs).

The initial hypothesis, documented in the local scratch file
`openpgp-card/issue.md`, pointed at
`openpgp-card::AlgorithmAttributes::ecc_algo_attrs` silently dropping
the `import_format` byte (`0xFF`) from the `set_algorithm_attributes`
APDU. A proposed patch restored the byte and was wired into
`libtumpa/Cargo.toml` via a `[patch.crates-io]` block. With that patch
**and** wecanencrypt's local-tree fixes (`0x40` prefix on Curve25519
public keys + an `(X25519, X25519)` match arm), the upload succeeded
end-to-end on both cards.

The openpgp-card maintainer (Heiko) responded on
[issue #128 comment 13701701](https://codeberg.org/openpgp-card/openpgp-card/issues/128#issuecomment-13701701)
with a three-part diagnosis:

1. **The `0xFF` in algo-attrs is not required by any known firmware.**
   GnuPG omits it for Curve25519 on Nitrokey 3 and succeeds. Direct
   APDU evidence from our own trace (`/tmp/pcscd_debug.log`) confirms
   this: stock openpgp-card 0.6.1 sends
   `00 DA 00 C1 00 00 0A 16 2B 06 01 04 01 DA 47 0F 01` (no trailing
   `FF`) and the Nitrokey 3 returns `SW 90 00`. The rejection that
   followed was on the *next* APDU (the import), not on the attrs write.
2. **The real blocker is the public-key parameter encoding inside the
   key-import body** (spec v3.4.1 §4.4.3.12 / §B.5):
   - EdDSA / ECDH Curve25519: `0x40 || point` (33 bytes).
   - ECDSA / ECDH NIST curves: `0x04 || x || y` (SEC1 uncompressed).
3. **That encoding is the consumer's responsibility.** The
   `openpgp-card-rpgp` crate did the equivalent fix in commit
   `2577a23`; wecanencrypt's counterpart lives in
   `wecanencrypt/src/card/upload.rs::extract_key_info`, which already
   wraps Curve25519 public keys with `ensure_curve25519_card_public_key_format`
   and converts NIST ECDSA/ECDH keys via `to_sec1_bytes()` /
   `to_encoded_point(false)`. No openpgp-card change is required.

Empirical re-verification after dropping the openpgp-card patch (stock
crates.io 0.6.1) while keeping the wecanencrypt path-dep: the same
`libtumpa/examples/upload_v4_x25519_cs.rs` against the Nitrokey 3
prints `✓ upload succeeded`.

## Decision

1. libtumpa will **not document the `0xFF` byte on algo-attrs** as a
   required contract of openpgp-card. Any future session that
   rediscovers `SW 6A80` on key-import against opcard-rs ≥1.5 should
   look at the public-key encoding in wecanencrypt first, not at the
   algo-attrs byte.

## Consequences

### Positive

- No maintenance burden of a private openpgp-card fork.
- We follow upstream's actual guidance, which keeps libtumpa aligned
  with `openpgp-card-rpgp` and any other rpgp-based consumer.
- When a new ECC variant is added to wecanencrypt's `extract_key_info`
  match, the single, well-known helper
  (`ensure_curve25519_card_public_key_format` or SEC1 encoding) is the
  only place to touch — the fix surface is confined to one crate.

### Negative / follow-ups

- Existing Cv25519 (legacy) uploads worked accidentally because rpgp's
  legacy EdDSA MPI already carries the `0x40` byte. That accident
  provides no forward guarantee — the fix must still go through
  `ensure_curve25519_card_public_key_format` to stay correct across
  rpgp internal representation changes.

## References

- [openpgp-card#128](https://codeberg.org/openpgp-card/openpgp-card/issues/128)
  and [comment 13701701](https://codeberg.org/openpgp-card/openpgp-card/issues/128#issuecomment-13701701).
- OpenPGP Smart Card Application Functional Specification v3.4.1,
  §4.4.3.9 (Algorithm Attributes) and §4.4.3.12 / §B.5 (Private Key
  Template / point encoding).
- `openpgp-card-rpgp` commit `2577a23` — equivalent downstream fix.
- Reproducer: [`libtumpa/examples/upload_v4_x25519_cs.rs`](../../examples/upload_v4_x25519_cs.rs).
- Wecanencrypt implementation: `wecanencrypt/src/card/upload.rs`
  (`extract_key_info` + `ensure_curve25519_card_public_key_format`).
