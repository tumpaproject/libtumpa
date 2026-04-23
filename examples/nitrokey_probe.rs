//! Read-only probe: confirm that the Nitrokey upload guard's detection
//! path fires on a real attached card, without touching any destructive
//! operation (no reset, no upload, no PIN writes).
//!
//! Run with: `cargo run --example nitrokey_probe --features card`

#[cfg(feature = "card")]
fn main() {
    use libtumpa::card::{get_card_details, list_all_cards};

    let cards = match list_all_cards() {
        Ok(cards) => cards,
        Err(e) => {
            eprintln!("list_all_cards failed: {e}");
            std::process::exit(1);
        }
    };

    println!("connected cards: {}", cards.len());
    if cards.is_empty() {
        eprintln!("no cards found — attach one and try again");
        std::process::exit(1);
    }

    let mut found_nitrokey = false;
    for c in &cards {
        println!(
            "  ident={}  manufacturer_name={}",
            c.ident, c.manufacturer_name
        );
        let info = match get_card_details(Some(&c.ident)) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("    get_card_details({}) failed: {e}", c.ident);
                continue;
            }
        };
        let mfg = info.manufacturer.as_deref().unwrap_or("<none>");
        let name = info.manufacturer_name.as_deref().unwrap_or("<none>");
        let is_nk = mfg.eq_ignore_ascii_case("000F");
        println!(
            "    manufacturer={mfg}  manufacturer_name={name}  is_nitrokey={is_nk}"
        );
        found_nitrokey |= is_nk;
    }

    if found_nitrokey {
        println!("\n✓ Nitrokey detected — guard would fire on incompatible algorithms");
    } else {
        println!("\n⚠ no Nitrokey (manufacturer=000F) among connected cards");
    }
}

#[cfg(not(feature = "card"))]
fn main() {
    eprintln!("build with `--features card` to run this probe");
    std::process::exit(1);
}
