//! Upload `tests/files/v4_x25519_cs_primary.asc` (passphrase
//! "redhat") to the connected OpenPGP card via libtumpa.
//!
//! The fixture has a Certify+Sign primary plus Encryption and
//! Authentication subkeys (no dedicated signing subkey), so the primary
//! is pushed into the signing slot.
//!
//! Run with: `cargo run --example upload_v4_x25519_cs --features card -- [ident]`
//! If multiple cards are connected, pass the ident (e.g. `000F:4E4B0001`)
//! as a positional argument.

#[cfg(feature = "card")]
fn main() {
    use libtumpa::card::upload::{self, flags};
    use libtumpa::{key, store, Passphrase};
    use std::path::PathBuf;

    env_logger::try_init().ok();

    let ident_arg: Option<String> = std::env::args().nth(1);
    let ident: Option<&str> = ident_arg.as_deref();

    let fixture: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("files")
        .join("v4_x25519_cs_primary.asc");

    let data = match std::fs::read(&fixture) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("read {:?}: {e}", fixture);
            std::process::exit(1);
        }
    };

    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tempdir: {e}");
            std::process::exit(1);
        }
    };
    let ks_path = tmp.path().join("keystore.db");
    let ks = match store::open_keystore(Some(&ks_path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open_keystore: {e}");
            std::process::exit(1);
        }
    };

    let info = match key::import_secret(&ks, &data) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("import_secret: {e}");
            std::process::exit(1);
        }
    };

    println!("imported fingerprint: {}", info.fingerprint);
    println!("can_primary_sign:     {}", info.can_primary_sign);
    println!("subkey count:         {}", info.subkeys.len());
    for sk in &info.subkeys {
        println!(
            "  subkey {}  key_type={:?}  algorithm={}",
            sk.fingerprint, sk.key_type, sk.algorithm
        );
    }

    let passphrase = Passphrase::new(String::from("redhat"));
    let which = flags::PRIMARY_TO_SIGNING | flags::ENCRYPTION | flags::AUTHENTICATION;

    println!(
        "\nuploading (primary→signing, encryption, authentication) ident={:?}...",
        ident
    );
    match upload::upload(&ks, &info.fingerprint, &passphrase, which, ident) {
        Ok(()) => {
            println!("✓ upload succeeded");
        }
        Err(e) => {
            eprintln!("✗ upload failed: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(feature = "card"))]
fn main() {
    eprintln!("build with `--features card` to run this example");
    std::process::exit(1);
}
