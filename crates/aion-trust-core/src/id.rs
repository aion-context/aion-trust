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
    /// Derive the did from a verifying key: `did:aion:` + the first 24 bytes of
    /// `hash(public_key)`. 24 bytes gives ~96-bit collision resistance (vs. 64-bit at 16),
    /// the trust anchor the registry keys on. Stable and reveals nothing personal.
    pub fn from_key(vk: &VerifyingKey) -> Self {
        let h = crypto::hash(&vk.to_bytes());
        Did(format!("did:aion:{}", to_hex(&h[..24])))
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

#[cfg(test)]
mod tests {
    use super::*;
    use aion_context::crypto::SigningKey;

    fn fresh_key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    #[test]
    fn did_is_deterministic_and_key_bound() {
        let k = fresh_key();
        assert_eq!(Did::from_key(&k), Did::from_key(&k)); // same key → same did
        assert_ne!(Did::from_key(&k), Did::from_key(&fresh_key())); // different key → different
        let d = Did::from_key(&k);
        assert!(d.as_str().starts_with("did:aion:")); // pins as_str (kills "" / "xyzzy")
        assert_eq!(d.as_bytes(), d.as_str().as_bytes()); // pins as_bytes
        assert_eq!(format!("{d}"), d.as_str().to_string()); // pins Display
    }

    #[test]
    fn did_from_string_preserves_input() {
        let d = Did::from_string("did:aion:abc".to_string());
        assert_eq!(d.as_str(), "did:aion:abc");
    }

    #[test]
    fn claim_id_is_content_addressed() {
        assert_eq!(
            ClaimId::from_signing_bytes(b"abc"),
            ClaimId::from_signing_bytes(b"abc")
        );
        assert_ne!(
            ClaimId::from_signing_bytes(b"abc"),
            ClaimId::from_signing_bytes(b"abd")
        );
        // pins as_str: non-empty and not the mutation sentinel
        let id = ClaimId::from_signing_bytes(b"abc");
        assert!(!id.as_str().is_empty());
        assert_ne!(id.as_str(), "xyzzy");
    }
}
