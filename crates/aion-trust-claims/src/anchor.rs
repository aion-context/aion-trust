//! The trust anchor a verifier consults during verification.
//!
//! It answers three questions per claim: *do I hold this issuer's key?* (authenticity),
//! *is this issuer accredited for this category?* (authority), and *has this claim been
//! revoked?* An [`IssuerDirectory`](crate::IssuerDirectory) is the simplest anchor —
//! recognized issuers, no accreditation, no revocation. The `aion-trust-registry` `Registry`
//! is the full anchor: K-of-N accreditation and epoch-scoped revocation.

use aion_context::crypto::VerifyingKey;
use aion_trust_core::{ClaimId, Did, Timestamp};

/// An issuer's standing for a given claim category at a given time.
pub struct IssuerStanding {
    /// A valid accreditation authorizes this issuer for the category (authoritative).
    pub accredited: bool,
    /// Whether this category *requires* accreditation to be accepted (high-assurance).
    pub accreditation_required: bool,
}

/// What a verifier consults to decide authenticity, authority, and revocation.
pub trait TrustAnchor {
    /// The trusted public key for an issuer, if it is recognized.
    fn issuer_key(&self, issuer: &Did) -> Option<VerifyingKey>;
    /// The issuer's standing for `category` as of `now`.
    fn standing(&self, issuer: &Did, category: &str, now: Timestamp) -> IssuerStanding;
    /// Whether the claim has been revoked as of `now`.
    fn is_revoked(&self, claim_id: &ClaimId, now: Timestamp) -> bool;
}
