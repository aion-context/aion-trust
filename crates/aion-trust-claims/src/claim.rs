//! The [`Claim`]: an issuer's signed attestation about a subject, with a verify-before-trust
//! typestate. The PII-bearing [`ClaimBody`] is private; only a [`VerifiedClaim`] — produced
//! solely by a successful signature check — exposes it. The category and schema are functions
//! of the body, so a claim cannot mislabel its own type.

use aion_context::crypto::{self, VerifyingKey};
use aion_trust_core::encoding::{decode_array, from_hex, to_hex, SigningWriter};
use aion_trust_core::{ClaimId, Did, Identity, Timestamp};
use serde::{Deserialize, Serialize};

use crate::bodies::ClaimBody;

pub const CLAIM_DOMAIN: &[u8] = b"aion-trust/claim/v1";
pub const BODY_DOMAIN: &[u8] = b"aion-trust/claim-body/v1";

/// The time window a claim asserts. `until: None` means open-ended / current.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub from: Timestamp,
    pub until: Option<Timestamp>,
}

impl Validity {
    pub fn active_at(&self, now: Timestamp) -> bool {
        now >= self.from && self.until.is_none_or(|u| now <= u)
    }
}

/// Why a claim failed verification — specific, so a verifier can explain the rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimReject {
    IssuerKeyMismatch,
    BodyTampered,
    ClaimIdMismatch,
    BadSignature,
    Malformed,
}

impl std::fmt::Display for ClaimReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ClaimReject::IssuerKeyMismatch => "issuer key does not match issuer_id",
            ClaimReject::BodyTampered => "body does not match signed body_hash",
            ClaimReject::ClaimIdMismatch => "claim_id does not match signed content",
            ClaimReject::BadSignature => "issuer signature is invalid",
            ClaimReject::Malformed => "claim is malformed",
        };
        f.write_str(s)
    }
}

/// A signed claim as issued, stored, and transmitted. The `body` is private: read it only
/// through a [`VerifiedClaim`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: ClaimId,
    pub subject_id: Did,
    pub issuer_id: Did,
    pub validity: Validity,
    body: ClaimBody,
    /// Random per-claim salt for the body commitment. Lives with the claim in the wallet,
    /// never on the ledger — it makes `body_hash`/`claim_id` a *hiding* commitment rather
    /// than a guessable fingerprint of low-entropy PII.
    pub salt: String,
    pub body_hash: String,
    pub issuer_signature: String,
}

impl Claim {
    /// Issue (sign) a claim of any category for `subject`. The issuer signs the
    /// domain-separated content; `claim_id` is the content hash.
    pub fn issue(
        issuer: &Identity,
        subject: &Did,
        validity: Validity,
        body: ClaimBody,
    ) -> Result<Claim, ClaimReject> {
        let salt = aion_context::crypto::generate_nonce();
        let body_hash = hash_body(&salt, &body)?;
        let signing = signing_bytes(subject, &issuer.did(), &body, &validity, &body_hash);
        Ok(Claim {
            claim_id: ClaimId::from_signing_bytes(&signing),
            subject_id: subject.clone(),
            issuer_id: issuer.did(),
            validity,
            body,
            salt: to_hex(&salt),
            body_hash: to_hex(&body_hash),
            issuer_signature: to_hex(&issuer.sign(&signing)),
        })
    }

    /// The issuer this claim *claims* to be from — used to resolve the trusted key. Reading
    /// it does not imply trust; verification still decides.
    pub fn issuer_id(&self) -> &Did {
        &self.issuer_id
    }

    pub fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }

    /// The category (employment, background_check, …) — safe to read pre-verification for
    /// routing; it does not expose the body.
    pub fn category(&self) -> &'static str {
        self.body.category()
    }

    /// Verify this claim against the issuer's trusted key. On success returns a
    /// [`VerifiedClaim`] — the only way to read the body.
    pub fn verify(&self, issuer_vk: &VerifyingKey) -> Result<VerifiedClaim, ClaimReject> {
        if Did::from_key(issuer_vk) != self.issuer_id {
            return Err(ClaimReject::IssuerKeyMismatch);
        }
        let salt = from_hex(&self.salt).map_err(|_| ClaimReject::Malformed)?;
        let body_hash = hash_body(&salt, &self.body)?;
        if to_hex(&body_hash) != self.body_hash {
            return Err(ClaimReject::BodyTampered);
        }
        let signing = signing_bytes(
            &self.subject_id,
            &self.issuer_id,
            &self.body,
            &self.validity,
            &body_hash,
        );
        if ClaimId::from_signing_bytes(&signing) != self.claim_id {
            return Err(ClaimReject::ClaimIdMismatch);
        }
        let sig = decode_array::<64>(&self.issuer_signature).map_err(|_| ClaimReject::Malformed)?;
        issuer_vk
            .verify(&signing, &sig)
            .map_err(|_| ClaimReject::BadSignature)?;
        Ok(VerifiedClaim(self.clone()))
    }
}

/// A claim whose issuer signature has been checked. The body is now safe to read.
pub struct VerifiedClaim(Claim);

impl VerifiedClaim {
    pub fn subject_id(&self) -> &Did {
        &self.0.subject_id
    }
    pub fn issuer_id(&self) -> &Did {
        &self.0.issuer_id
    }
    pub fn claim_id(&self) -> &ClaimId {
        &self.0.claim_id
    }
    pub fn category(&self) -> &'static str {
        self.0.body.category()
    }
    pub fn validity(&self) -> &Validity {
        &self.0.validity
    }
    /// The trusted body — reachable only after verification.
    pub fn body(&self) -> &ClaimBody {
        &self.0.body
    }
    pub fn active_at(&self, now: Timestamp) -> bool {
        self.0.validity.active_at(now)
    }
}

/// A salted, canonical (RFC 8785 / JCS) commitment to the body. Canonical so the hash is
/// reproducible across serializers and languages; salted so it is a hiding commitment, not a
/// guessable fingerprint of low-entropy PII.
fn hash_body(salt: &[u8], body: &ClaimBody) -> Result<[u8; 32], ClaimReject> {
    let canonical = aion_context::jcs::to_jcs_bytes(body).map_err(|_| ClaimReject::Malformed)?;
    let mut w = SigningWriter::new(BODY_DOMAIN);
    w.field(salt).field(&canonical);
    Ok(crypto::hash(&w.into_bytes()))
}

fn signing_bytes(
    subject: &Did,
    issuer: &Did,
    body: &ClaimBody,
    validity: &Validity,
    body_hash: &[u8; 32],
) -> Vec<u8> {
    let mut w = SigningWriter::new(CLAIM_DOMAIN);
    w.field(subject.as_bytes())
        .field(issuer.as_bytes())
        .field(body.category().as_bytes())
        .field(body.schema_id().as_bytes())
        .int(validity.from.0);
    match validity.until {
        Some(t) => {
            w.field(b"until").int(t.0);
        }
        None => {
            w.field(b"open");
        }
    }
    w.field(body_hash);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::{EmploymentBody, SkillBody};
    use aion_trust_core::Identity;

    fn employment() -> ClaimBody {
        ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Senior Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021-03-01".into(),
            end: None,
            rehire_eligible: true,
        })
    }

    #[test]
    fn reject_messages_are_specific() {
        assert!(ClaimReject::BodyTampered.to_string().contains("body"));
        assert_ne!(
            ClaimReject::BadSignature.to_string(),
            ClaimReject::BodyTampered.to_string()
        );
    }

    #[test]
    fn validity_active_at_boundaries() {
        let v = Validity {
            from: Timestamp(10),
            until: Some(Timestamp(20)),
        };
        assert!(!v.active_at(Timestamp(9)));
        assert!(v.active_at(Timestamp(10)));
        assert!(v.active_at(Timestamp(20)));
        assert!(!v.active_at(Timestamp(21)));
        let open = Validity {
            from: Timestamp(10),
            until: None,
        };
        assert!(open.active_at(Timestamp(1_000)));
        assert!(!open.active_at(Timestamp(9)));
    }

    #[test]
    fn hash_body_binds_salt_and_body() {
        let b = employment();
        let h = hash_body(b"salt-1", &b).unwrap();
        assert_ne!(h, hash_body(b"salt-2", &b).unwrap()); // salt is a hiding nonce
        let other = ClaimBody::Skill(SkillBody {
            skill: "Rust".into(),
            level: None,
        });
        assert_ne!(h, hash_body(b"salt-1", &other).unwrap()); // body content matters
    }

    #[test]
    fn signing_bytes_is_nonempty_and_binds_every_field() {
        let s = Did::from_string("did:aion:subject".into());
        let i = Did::from_string("did:aion:issuer".into());
        let v = Validity {
            from: Timestamp(1),
            until: None,
        };
        let h = [7u8; 32];
        let body = employment();
        let base = signing_bytes(&s, &i, &body, &v, &h);
        assert!(!base.is_empty());
        let other = Did::from_string("did:aion:other".into());
        assert_ne!(base, signing_bytes(&other, &i, &body, &v, &h));
        assert_ne!(base, signing_bytes(&s, &other, &body, &v, &h));
        let skill = ClaimBody::Skill(SkillBody {
            skill: "Rust".into(),
            level: None,
        });
        assert_ne!(base, signing_bytes(&s, &i, &skill, &v, &h)); // category bound
        let v_from = Validity {
            from: Timestamp(2),
            until: None,
        };
        assert_ne!(base, signing_bytes(&s, &i, &body, &v_from, &h));
        let v_until = Validity {
            from: Timestamp(1),
            until: Some(Timestamp(9)),
        };
        assert_ne!(base, signing_bytes(&s, &i, &body, &v_until, &h)); // open vs until arm
        assert_ne!(base, signing_bytes(&s, &i, &body, &v, &[8u8; 32]));
    }

    #[test]
    fn issue_then_verify_exposes_the_body() {
        let issuer = Identity::generate();
        let subject = Did::from_string("did:aion:subj".into());
        let validity = Validity {
            from: Timestamp(0),
            until: None,
        };
        let claim = Claim::issue(&issuer, &subject, validity, employment()).unwrap();
        assert_eq!(claim.category(), "employment");
        let verified = claim.verify(&issuer.verifying_key()).expect("verify");
        assert_eq!(verified.subject_id(), &subject);
        assert_eq!(verified.category(), "employment");
        match verified.body() {
            ClaimBody::Employment(e) => assert_eq!(e.title, "Senior Engineer"),
            _ => panic!("wrong body"),
        }
    }
}
