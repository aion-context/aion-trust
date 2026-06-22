//! The crate's typed error. Library code returns `Result`; it never panics.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InteropError {
    /// A required JSON field is absent.
    #[error("missing field: {0}")]
    MissingField(&'static str),

    /// A JSON field has the wrong type/shape.
    #[error("wrong type for field: {0}")]
    WrongType(&'static str),

    /// A `did:key` could not be decoded (bad multibase/multicodec/length/curve point).
    #[error("did:key: {0}")]
    DidKey(String),

    /// An RFC3339 timestamp could not be parsed or formatted.
    #[error("rfc3339: {0}")]
    Rfc3339(String),

    /// The `did:key` public key did not derive the `did:aion` claimed in the document — the
    /// key-substitution defense (an artifact claiming issuer X but signed by another key).
    #[error("did binding mismatch: claimed {expected}, key derives {derived}")]
    DidBinding { expected: String, derived: String },

    /// No public key could be resolved for an issuer during VP export.
    #[error("could not resolve issuer key for {0}")]
    UnresolvedIssuer(String),

    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The reconstructed artifact failed aion-trust's native verification.
    #[error("verification failed: {0}")]
    Verify(String),

    /// A core crypto/encoding operation failed.
    #[error(transparent)]
    Trust(#[from] aion_trust_core::TrustError),
}

pub type Result<T> = std::result::Result<T, InteropError>;
