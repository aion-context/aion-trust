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

/// The resolvable status of a claim as of a given time. `Unresolvable` is the honest third state:
/// an anchor that *cannot determine* a claim's status must say so, so the dependency (fifth) check
/// fails closed rather than silently treating "unknown" as "live" (a fail-open hole). See
/// `docs/DEPENDENCY-TRUST.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimStatus {
    Live,
    Revoked,
    Unresolvable,
}

/// What a verifier consults to decide authenticity, authority, and revocation.
pub trait TrustAnchor {
    /// The trusted public key for an issuer, if it is recognized.
    fn issuer_key(&self, issuer: &Did) -> Option<VerifyingKey>;
    /// The issuer's standing for `category` as of `now`.
    fn standing(&self, issuer: &Did, category: &str, now: Timestamp) -> IssuerStanding;
    /// Whether the claim has been revoked as of `now`.
    fn is_revoked(&self, claim_id: &ClaimId, now: Timestamp) -> bool;
    /// The claim's resolvable status as of `now`. Defaults to deriving from [`Self::is_revoked`]
    /// (`Live`/`Revoked`), so existing anchors are unchanged; an anchor that can distinguish
    /// "cannot resolve this claim" overrides this to return [`ClaimStatus::Unresolvable`], which
    /// the dependency check treats as fail-closed.
    fn status(&self, claim_id: &ClaimId, now: Timestamp) -> ClaimStatus {
        if self.is_revoked(claim_id, now) {
            ClaimStatus::Revoked
        } else {
            ClaimStatus::Live
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An anchor that only implements `is_revoked`, so it exercises the default `status`.
    struct RevokeAnchor(bool);
    impl TrustAnchor for RevokeAnchor {
        fn issuer_key(&self, _issuer: &Did) -> Option<VerifyingKey> {
            None
        }
        fn standing(&self, _issuer: &Did, _category: &str, _now: Timestamp) -> IssuerStanding {
            IssuerStanding {
                accredited: false,
                accreditation_required: false,
            }
        }
        fn is_revoked(&self, _claim_id: &ClaimId, _now: Timestamp) -> bool {
            self.0
        }
    }

    #[test]
    fn default_status_derives_from_is_revoked() {
        let id = ClaimId::from_signing_bytes(b"x");
        assert_eq!(
            RevokeAnchor(false).status(&id, Timestamp(0)),
            ClaimStatus::Live
        );
        assert_eq!(
            RevokeAnchor(true).status(&id, Timestamp(0)),
            ClaimStatus::Revoked
        );
    }
}
