//! Card integration tests against a live OpenPGP card.
//!
//! CI runs these against the `jcecard` Java-Card OpenPGP emulator (see
//! `.github/workflows/ci.yml`); locally, run with a connected hardware
//! card or a separately-launched jcecard instance:
//!
//!     cargo test --features card --test card_integration -- --ignored --test-threads=1
//!
//! Each test resets the card to factory defaults (admin PIN: 12345678,
//! user PIN: 123456) and uploads a freshly generated key, so the tests
//! can run in any order. `--test-threads=1` is required because a card
//! is a single serial device.

#![cfg(feature = "card")]

use libtumpa::{
    decrypt::{self, DecryptVerifyOutcome},
    encrypt, sign, KeyStore, Passphrase, Pin,
};
use wecanencrypt::card::{reset_card, upload_key_to_card, verify_admin_pin, CardKeySlot};
use wecanencrypt::{create_key_simple, parse_key_bytes};

const USER_PIN: &[u8] = b"123456";
const ADMIN_PIN: &[u8] = b"12345678";
const KEY_PASSWORD: &str = "pw";

/// Reset the card to factory defaults: blocks the admin PIN with three
/// wrong attempts and then issues `reset_card`. Mirrors the helper used
/// in wecanencrypt's own card_tests so libtumpa's tests don't inherit
/// state from a prior run.
fn reset_card_to_defaults() {
    for _ in 0..3 {
        let _ = verify_admin_pin(b"00000000", None);
    }
    reset_card(None).expect("card reset failed");
}

fn fresh_key_with_uploaded_slot(uid: &str, slot: CardKeySlot) -> (Vec<u8>, Vec<u8>) {
    let key = create_key_simple(KEY_PASSWORD, &[uid]).expect("create_key_simple failed");
    reset_card_to_defaults();
    upload_key_to_card(
        &key.secret_key,
        KEY_PASSWORD.as_bytes(),
        slot,
        ADMIN_PIN,
        None,
    )
    .expect("upload_key_to_card failed");
    (key.secret_key.to_vec(), key.public_key.into_bytes())
}

fn pw(s: &str) -> Passphrase {
    Passphrase::new(s.to_string())
}

fn pin(b: &[u8]) -> Pin {
    Pin::new(b.to_vec())
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn find_signing_card_finds_uploaded_key() {
    let (secret_key, _public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let m = sign::find_signing_card(&secret_key)
        .expect("find_signing_card errored")
        .expect("expected a card with the uploaded key");
    assert!(!m.card.ident.is_empty(), "card ident should not be empty");
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_detached_dispatches_to_card() {
    let (secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let info = parse_key_bytes(&secret_key, true).unwrap();

    let mut card_pin_requested = false;
    let mut passphrase_requested = false;

    let (sig, backend) = sign::sign_detached(&secret_key, &info, b"hello", |req| match req {
        sign::SecretRequest::CardPin { .. } => {
            card_pin_requested = true;
            Ok(sign::Secret::Pin(pin(USER_PIN)))
        }
        sign::SecretRequest::KeyPassphrase { .. } => {
            passphrase_requested = true;
            Ok(sign::Secret::Passphrase(pw(KEY_PASSWORD)))
        }
    })
    .expect("sign_detached failed");

    assert!(card_pin_requested, "card path should have been selected");
    assert!(!passphrase_requested, "software fallback should not run");
    assert_eq!(backend, sign::SignBackend::Card);

    let valid = wecanencrypt::verify_bytes_detached(&public_key, b"hello", sig.as_bytes())
        .expect("verify failed");
    assert!(valid, "signature did not verify");
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_detached_card_wrong_pin_falls_back_to_software() {
    let (secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let info = parse_key_bytes(&secret_key, true).unwrap();

    let mut card_pin_requested = false;
    let mut passphrase_requested = false;

    let (sig, backend) = sign::sign_detached(&secret_key, &info, b"data", |req| match req {
        sign::SecretRequest::CardPin { .. } => {
            card_pin_requested = true;
            Ok(sign::Secret::Pin(pin(b"00000000")))
        }
        sign::SecretRequest::KeyPassphrase { .. } => {
            passphrase_requested = true;
            Ok(sign::Secret::Passphrase(pw(KEY_PASSWORD)))
        }
    })
    .expect("sign_detached failed");

    assert!(card_pin_requested);
    assert!(passphrase_requested, "software fallback should run");
    assert_eq!(backend, sign::SignBackend::Software);

    let ok = wecanencrypt::verify_bytes_detached(&public_key, b"data", sig.as_bytes()).unwrap();
    assert!(ok);
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_detached_with_hash_card_reports_hash() {
    let (secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let info = parse_key_bytes(&secret_key, true).unwrap();

    // Card path ignores `hash_preference`; the card chose the hash and
    // the result reports what was actually used.
    let result = sign::sign_detached_with_hash(
        &secret_key,
        &info,
        b"payload",
        Some(libtumpa::HashAlgorithm::Sha256),
        |req| match req {
            sign::SecretRequest::CardPin { .. } => Ok(sign::Secret::Pin(pin(USER_PIN))),
            sign::SecretRequest::KeyPassphrase { .. } => panic!("software fallback unexpected"),
        },
    )
    .expect("sign_detached_with_hash failed");

    assert_eq!(result.backend, sign::SignBackend::Card);
    use libtumpa::HashAlgorithm::*;
    assert!(
        matches!(result.hash_algorithm, Sha256 | Sha384 | Sha512),
        "unexpected hash algorithm: {:?}",
        result.hash_algorithm
    );
    let ok =
        wecanencrypt::verify_bytes_detached(&public_key, b"payload", result.armored.as_bytes())
            .unwrap();
    assert!(ok);
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_cleartext_dispatches_to_card() {
    let (secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let info = parse_key_bytes(&secret_key, true).unwrap();

    let (signed, backend) = sign::sign_cleartext(&secret_key, &info, b"hello\n", |req| match req {
        sign::SecretRequest::CardPin { .. } => Ok(sign::Secret::Pin(pin(USER_PIN))),
        sign::SecretRequest::KeyPassphrase { .. } => panic!("should not request passphrase"),
    })
    .expect("sign_cleartext failed");

    assert_eq!(backend, sign::SignBackend::Card);
    let signed_str = std::str::from_utf8(&signed).unwrap();
    assert!(signed_str.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
    assert!(signed_str.contains("-----BEGIN PGP SIGNATURE-----"));

    let ok = wecanencrypt::verify_bytes(&public_key, &signed).unwrap();
    assert!(ok);
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_detached_on_card_low_level() {
    let (_secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let sig = sign::sign_detached_on_card(&public_key, b"low-level", &pin(USER_PIN), None)
        .expect("sign_detached_on_card failed");
    let ok =
        wecanencrypt::verify_bytes_detached(&public_key, b"low-level", sig.as_bytes()).unwrap();
    assert!(ok);
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_cleartext_on_card_low_level() {
    let (_secret_key, public_key) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);
    let signed = sign::sign_cleartext_on_card(&public_key, b"hello\n", &pin(USER_PIN), None)
        .expect("sign_cleartext_on_card failed");
    let ok = wecanencrypt::verify_bytes(&public_key, &signed).unwrap();
    assert!(ok);
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn find_decryption_card_finds_uploaded_key() {
    let (_secret_key, public_key) =
        fresh_key_with_uploaded_slot("Bob <bob@example.com>", CardKeySlot::Decryption);
    // `find_decryption_card` resolves matched fingerprints through the
    // store (`find_by_subkey_fingerprint`), so the public cert needs to
    // be present.
    let store = KeyStore::open_in_memory().unwrap();
    store.import_key(&public_key).unwrap();

    let ct = wecanencrypt::encrypt_bytes(&public_key, b"sealed", true).unwrap();
    let card = decrypt::find_decryption_card(&store, &ct)
        .expect("find_decryption_card errored")
        .expect("expected a card");
    assert!(!card.encryption_fingerprint.is_empty());
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn decrypt_on_card_low_level() {
    let (_secret_key, public_key) =
        fresh_key_with_uploaded_slot("Bob <bob@example.com>", CardKeySlot::Decryption);
    let ct = wecanencrypt::encrypt_bytes(&public_key, b"top-secret", true).unwrap();
    let pt = decrypt::decrypt_on_card(&public_key, &ct, &pin(USER_PIN), None)
        .expect("decrypt_on_card failed");
    assert_eq!(pt.as_slice(), b"top-secret");
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn decrypt_and_verify_on_card_good() {
    // Alice signs in software; Bob's encryption subkey lives on the card.
    let alice = create_key_simple("alice-pw", &["Alice <a@example.com>"]).unwrap();
    let (_bob_secret, bob_public) =
        fresh_key_with_uploaded_slot("Bob <b@example.com>", CardKeySlot::Decryption);

    let store = KeyStore::open_in_memory().unwrap();
    store.import_key(alice.public_key.as_bytes()).unwrap();
    store.import_key(&bob_public).unwrap();

    let ct = wecanencrypt::sign_and_encrypt_to_multiple(
        &alice.secret_key,
        "alice-pw",
        &[bob_public.as_slice()],
        b"signed and sealed",
        true,
    )
    .unwrap();

    let result =
        decrypt::decrypt_and_verify_on_card(&store, &bob_public, &ct, &pin(USER_PIN), None)
            .expect("decrypt_and_verify_on_card failed");
    assert_eq!(result.plaintext.as_slice(), b"signed and sealed");
    match result.outcome {
        DecryptVerifyOutcome::Good { key_info, .. } => {
            assert!(key_info
                .user_ids
                .iter()
                .any(|u| u.value.contains("a@example.com")));
        }
        other => panic!("expected Good, got {other:?}"),
    }
}

#[test]
#[ignore = "requires a connected OpenPGP card (or jcecard emulator)"]
fn sign_and_encrypt_on_card_to_recipients_roundtrip() {
    // Alice signs on the card; Bob receives in software.
    let bob = create_key_simple("bob-pw", &["Bob <b@example.com>"]).unwrap();
    let (_alice_secret, alice_public) =
        fresh_key_with_uploaded_slot("Alice <alice@example.com>", CardKeySlot::Signing);

    let store = KeyStore::open_in_memory().unwrap();
    store.import_key(&alice_public).unwrap();
    store.import_key(&bob.secret_key).unwrap();

    let ct = encrypt::sign_and_encrypt_on_card_to_recipients(
        &store,
        &alice_public,
        &pin(USER_PIN),
        None,
        &["b@example.com"],
        b"hello, signed by card",
        true,
    )
    .expect("sign_and_encrypt_on_card_to_recipients failed");

    let result =
        decrypt::decrypt_and_verify_with_key(&store, &bob.secret_key, &ct, &pw("bob-pw")).unwrap();
    assert_eq!(result.plaintext.as_slice(), b"hello, signed by card");
    match result.outcome {
        DecryptVerifyOutcome::Good { key_info, .. } => {
            assert!(key_info
                .user_ids
                .iter()
                .any(|u| u.value.contains("alice@example.com")));
        }
        other => panic!("expected Good, got {other:?}"),
    }
}
