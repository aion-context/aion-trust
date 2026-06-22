//! aion-trust-core — the primitives every other crate shares: cryptographic
//! identities, key-derived ids, deterministic signing-byte encoding, and errors.
//!
//! Nothing here knows about claims or résumés; it is the thin layer over
//! `aion-context` crypto that the domain crates build on.

pub mod encoding;
pub mod error;
pub mod id;
pub mod identity;
pub mod merkle;
pub mod time;

pub use error::{Result, TrustError};
pub use id::{ClaimId, Did};
pub use identity::Identity;
pub use time::Timestamp;
