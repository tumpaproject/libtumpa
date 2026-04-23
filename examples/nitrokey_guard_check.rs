//! Non-destructive end-to-end check: feed the real attached Nitrokey a
//! `Cv25519` (legacy) cert through `libtumpa::card::upload::upload` and
//! confirm it errors with `Error::CardUnsupportedAlgorithm` BEFORE any
//! destructive operation (reset, PIN write, key install) runs.
//!
//! Safe to run on a provisioned Nitrokey: the guard fires before
//! `reset_card` is called. If this example ever wipes your card, that
//! is a bug — the guard has regressed.
//!
//! Run with: `cargo run --example nitrokey_guard_check --features card`

#[cfg(feature = "card")]
fn main() {
    use libtumpa::card::list_all_cards;
    use libtumpa::card::upload::{flags, upload};
    use libtumpa::{Error, Passphrase};
    use wecanencrypt::{create_key_simple, CipherSuite, KeyStore};

    let cards = list_all_cards().expect("list_all_cards");
    let nk = cards
        .iter()
        .find(|c| c.ident.to_uppercase().starts_with("000F:"))
        .expect("no Nitrokey (manufacturer 000F) attached");
    println!("using Nitrokey ident={}", nk.ident);

    // Cv25519 legacy = EdDSALegacy primary + ECDH/Curve25519 encryption.
    // Nitrokey is expected to reject this in libtumpa's preflight guard.
    let key = {
        // create_key_simple defaults to CipherSuite::Cv25519 (legacy).
        let _ = CipherSuite::Cv25519; // explicit acknowledgement
        create_key_simple("pw", &["Alice <a@e.com>"]).expect("create_key_simple")
    };
    let store = KeyStore::open_in_memory().expect("keystore");
    store.import_key(&key.secret_key).expect("import_key");

    let fp = {
        let info = wecanencrypt::parse_key_bytes(&key.secret_key, true).unwrap();
        info.fingerprint
    };

    let pw = Passphrase::new("pw".to_string());
    let which = flags::PRIMARY_TO_SIGNING | flags::ENCRYPTION | flags::AUTHENTICATION;

    match upload(&store, &fp, &pw, which, Some(&nk.ident)) {
        Err(Error::CardUnsupportedAlgorithm { card, algorithm }) => {
            println!(
                "✓ guard fired before any destructive op: \
                 card={card:?} rejected algorithm={algorithm:?}"
            );
        }
        Err(other) => {
            eprintln!("✗ wrong error path: {other}");
            std::process::exit(1);
        }
        Ok(()) => {
            eprintln!(
                "✗ upload unexpectedly succeeded — guard failed to fire, \
                 your card may have been reset!"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(not(feature = "card"))]
fn main() {
    eprintln!("build with `--features card` to run this probe");
    std::process::exit(1);
}
