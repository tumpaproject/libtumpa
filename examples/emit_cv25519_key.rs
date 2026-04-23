//! Throwaway: emit a Cv25519 (legacy) secret key to stdout as raw
//! binary bytes. Used to exercise the Nitrokey-rejection path
//! end-to-end via tcli.
use wecanencrypt::create_key_simple;

fn main() {
    let key = create_key_simple("pw", &["Alice <alice@example.com>"]).expect("create_key_simple");
    // tcli --import accepts the secret key bytes directly (binary).
    std::io::Write::write_all(&mut std::io::stdout(), &key.secret_key).expect("stdout write");
}
