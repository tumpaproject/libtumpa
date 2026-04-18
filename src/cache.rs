//! In-memory credential cache (passphrases and card PINs).
//!
//! Lifted from `tumpa-cli/src/cache.rs`.

use std::collections::HashMap;
use std::time::Instant;

use zeroize::Zeroizing;

struct CacheEntry {
    value: Zeroizing<String>,
    stored_at: Instant,
}

/// In-memory cache for passphrases and card PINs.
///
/// - Card PINs are keyed by card ident (e.g., `"MANUFACTURER:SERIAL"`)
/// - Software key passphrases are keyed by certificate fingerprint
///
/// All values use [`Zeroizing<String>`] for automatic zeroing on drop.
/// Entries can be expired via [`CredentialCache::sweep`].
#[derive(Default)]
pub struct CredentialCache {
    entries: HashMap<String, CacheEntry>,
}

impl CredentialCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, key: &str, value: Zeroizing<String>) {
        self.entries.insert(
            key.to_string(),
            CacheEntry {
                value,
                stored_at: Instant::now(),
            },
        );
    }

    pub fn get(&self, key: &str) -> Option<&Zeroizing<String>> {
        self.entries.get(key).map(|e| &e.value)
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Clear all cached credentials for a specific card ident.
    /// Called when a card is disconnected/reconnected to force re-prompting
    /// the PIN.
    pub fn clear_card(&mut self, card_ident: &str) {
        self.entries.remove(card_ident);
    }

    /// Remove all entries older than `ttl_secs` seconds.
    /// Returns the number of entries removed.
    pub fn sweep(&mut self, ttl_secs: u64) -> usize {
        let cutoff = Instant::now() - std::time::Duration::from_secs(ttl_secs);
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.stored_at > cutoff);
        before - self.entries.len()
    }
}
