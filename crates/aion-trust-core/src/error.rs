//! The crate's typed error. Libraries return `Result`; they never panic.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    /// A cryptographic operation in `aion-context` failed.
    #[error("crypto: {0}")]
    Crypto(#[from] aion_context::AionError),

    /// Hex/byte decoding failed (wrong length, bad characters).
    #[error("decode: {0}")]
    Decode(String),

    /// JSON (de)serialization of a claim or presentation failed.
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),

    /// Filesystem access failed (CLI key/artifact files).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TrustError>;
