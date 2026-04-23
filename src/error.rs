use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("keystore error: {0}")]
    KeyStore(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key {fingerprint} is unusable: {reason}")]
    UnusableKey { fingerprint: String, reason: String },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("card not connected")]
    CardNotConnected,

    #[error("card error: {0}")]
    Card(String),

    #[error("{card} does not support {algorithm}")]
    CardUnsupportedAlgorithm { card: String, algorithm: String },

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("verification failed: {0}")]
    Verify(String),

    #[error("encryption failed: {0}")]
    Encrypt(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("network error: {0}")]
    #[cfg(feature = "network")]
    Network(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Wecanencrypt(#[from] wecanencrypt::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn unusable(fp: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::UnusableKey {
            fingerprint: fp.into(),
            reason: reason.into(),
        }
    }
}
