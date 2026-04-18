//! Cross-module end-to-end workflow tests.
//!
//! Every test uses [`KeyStore::open_in_memory`] so the tumpa `~/.tumpa`
//! directory is never touched.

use chrono::{Duration, Utc};
use libtumpa::{
    decrypt, encrypt, key,
    sign::{self, SecretRequest, SignBackend},
    store, verify,
    KeyStore, SubkeyFlags,
};

fn in_memory_store() -> KeyStore {
    KeyStore::open_in_memory().unwrap()
}

#[test]
fn full_software_workflow() {
    let store = in_memory_store();

    // Generate & import.
    let params = key::GenerateKeyParams {
        uids: vec!["Alice <alice@example.com>".into()],
        subkey_flags: SubkeyFlags::all(),
        ..Default::default()
    };
    let info = key::generate_and_import(&store, params, "pw").unwrap();
    let fp = info.fingerprint.clone();
    assert!(info.is_secret);

    // Resolve via store helpers.
    let (_data, resolved) = store::resolve_signer(&store, &fp).unwrap();
    assert_eq!(resolved.fingerprint, fp);
    store::ensure_key_usable_for_signing(&resolved).unwrap();
    store::ensure_key_usable_for_encryption(&resolved).unwrap();

    // Sign via high-level dispatch (software, because no card).
    let (raw, key_info) = store.get_key(&fp).unwrap();
    let (signature, backend) = sign::sign_detached(&raw, &key_info, b"payload", |req| {
        match req {
            SecretRequest::KeyPassphrase { .. } => {
                Ok(zeroize::Zeroizing::new(b"pw".to_vec()))
            }
            SecretRequest::CardPin { .. } => panic!("unexpected card path"),
        }
    })
    .unwrap();
    assert_eq!(backend, SignBackend::Software);

    // Verify against store.
    let outcome = verify::verify_detached(&store, b"payload", signature.as_bytes()).unwrap();
    assert!(matches!(outcome, verify::VerifyOutcome::Good { .. }));

    // Encrypt → decrypt round-trip.
    let ct = encrypt::encrypt_to_recipients(&store, &[&fp], b"top-secret", true).unwrap();
    let key_ids = decrypt::recipients_of(&ct).unwrap();
    assert!(!key_ids.is_empty());
    let (key_data, _) = decrypt::find_software_decryption_key(&store, &ct)
        .unwrap()
        .expect("should find secret key");
    let pt = decrypt::decrypt_with_key(&key_data, &ct, "pw").unwrap();
    assert_eq!(pt.as_slice(), b"top-secret");
}

#[test]
fn uid_lifecycle() {
    let store = in_memory_store();
    let info = key::generate_and_import(
        &store,
        key::GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        },
        "pw",
    )
    .unwrap();

    let info = key::add_uid(&store, &info.fingerprint, "Alice 2 <a2@example.com>", "pw").unwrap();
    assert_eq!(info.user_ids.len(), 2);

    let info = key::revoke_uid(&store, &info.fingerprint, "Alice 2 <a2@example.com>", "pw").unwrap();
    assert!(info
        .user_ids
        .iter()
        .find(|u| u.value == "Alice 2 <a2@example.com>")
        .unwrap()
        .revoked);
}

#[test]
fn expiry_updates_propagate_to_subkeys() {
    let store = in_memory_store();
    let info = key::generate_and_import(
        &store,
        key::GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        },
        "pw",
    )
    .unwrap();

    let new_expiry = Utc::now() + Duration::days(365);
    let updated = key::update_expiry(&store, &info.fingerprint, new_expiry, "pw").unwrap();

    assert!(updated.expiration_time.is_some());
    for sk in &updated.subkeys {
        assert!(sk.expiration_time.is_some());
    }
}

#[test]
fn availability_reflects_subkey_state() {
    let store = in_memory_store();
    let info = key::generate_and_import(
        &store,
        key::GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            subkey_flags: SubkeyFlags {
                encryption: true,
                signing: true,
                authentication: true,
            },
            ..Default::default()
        },
        "pw",
    )
    .unwrap();

    let avail = key::available_subkeys(&store, &info.fingerprint).unwrap();
    assert!(avail.encryption);
    assert!(avail.signing_subkey);
    assert!(avail.authentication);
}

#[cfg(feature = "card")]
#[test]
fn card_links_persist_in_card_keys_table() {
    use libtumpa::card::link as card_link;
    use wecanencrypt::card::CardInfo;

    let store = in_memory_store();
    let info = key::generate_and_import(
        &store,
        key::GenerateKeyParams {
            uids: vec!["Alice <alice@example.com>".into()],
            ..Default::default()
        },
        "pw",
    )
    .unwrap();

    let card = CardInfo {
        ident: "0006:00000001".into(),
        serial_number: "00000001".into(),
        cardholder_name: Some("Alice".into()),
        public_key_url: None,
        pin_retry_counter: 3,
        reset_code_retry_counter: 3,
        admin_pin_retry_counter: 3,
        signature_fingerprint: Some(info.fingerprint.clone()),
        encryption_fingerprint: None,
        authentication_fingerprint: None,
        signature_counter: 0,
        manufacturer: Some("0006".into()),
        manufacturer_name: Some("TestCo".into()),
    };

    card_link::link(
        &store,
        &info.fingerprint,
        &card,
        "signature",
        &info.fingerprint,
    )
    .unwrap();

    let idents = card_link::card_idents_for_key(&store, &info.fingerprint).unwrap();
    assert_eq!(idents, vec!["0006:00000001"]);

    // Unlinking removes the row.
    card_link::unlink_card(&store, "0006:00000001").unwrap();
    assert!(card_link::card_idents_for_key(&store, &info.fingerprint)
        .unwrap()
        .is_empty());
}
