//! Key-derived identifiers. A `Did` is the public, stable handle for an identity
//! (subject or issuer); a `ClaimId` is the opaque content hash the ledger keys on.
//! Neither carries PII.

use aion_context::crypto::{self, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::encoding::to_hex;

/// A decentralized identifier of the form `did:aion:<hex>`, derived from a public key.
/// Used for both subject and issuer ids — it is the same kind of thing in each role.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Derive the did from a verifying key: `did:aion:` + the first 16 bytes of
    /// `hash(public_key)`. Stable, collision-resistant, and reveals nothing personal.
    pub fn from_key(vk: &VerifyingKey) -> Self {
        let h = crypto::hash(&vk.to_bytes());
        Did(format!("did:aion:{}", to_hex(&h[..16])))
    }

    /// Wrap a did string supplied by a user (e.g. an issuer naming the subject). The binding
    /// to an actual key is still enforced at verification, so this cannot fabricate trust.
    pub fn from_string(s: String) -> Self {
        Did(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The opaque content id of a claim: hex of `hash(signing_bytes)`. The only handle the
/// ledger keys claim status on; carries no PII.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimId(String);

impl ClaimId {
    pub fn from_signing_bytes(bytes: &[u8]) -> Self {
        ClaimId(to_hex(&crypto::hash(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
