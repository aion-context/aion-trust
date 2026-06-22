//! The [`Claim`]: an issuer's signed attestation about a subject, with a verify-before-
//! trust typestate. The PII-bearing `body` is private; only a [`VerifiedClaim`] — which can
//! only be produced by a successful signature check — exposes it.

use aion_context::crypto::{self, VerifyingKey};
use aion_trust_core::encoding::{decode_array, to_hex, SigningWriter};
use aion_trust_core::{ClaimId, Did, Identity, Timestamp};
use serde::{Deserialize, Serialize};

pub const CLAIM_DOMAIN: &[u8] = b"aion-trust/claim/v1";
pub const SCHEMA_EMPLOYMENT: &str = "aion-trust/employment/v1";

/// The category of a claim. Phase 1 ships `Employment`; the enum is the extension point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    Employment,
}

impl ClaimType {
    fn tag(&self) -> &'static [u8] {
        match self {
            ClaimType::Employment => b"employment",
        }
    }
}

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

/// The employment claim body — the PII-bearing payload. Never written to the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentBody {
    pub employer: String,
    pub title: String,
    pub employment_type: String,
    pub start: String,
    pub end: Option<String>,
    pub rehire_eligible: bool,
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
    pub claim_type: ClaimType,
    pub schema_id: String,
    pub subject_id: Did,
    pub issuer_id: Did,
    pub validity: Validity,
    body: EmploymentBody,
    pub body_hash: String,
    pub issuer_signature: String,
}

impl Claim {
    /// Issue (sign) an employment claim for `subject`. The issuer signs the domain-
    /// separated content; `claim_id` is the content hash.
    pub fn issue(
        issuer: &Identity,
        subject: &Did,
        validity: Validity,
        body: EmploymentBody,
    ) -> Result<Claim, ClaimReject> {
        let body_hash = hash_body(&body)?;
        let signing = signing_bytes(
            subject,
            &issuer.did(),
            &ClaimType::Employment,
            SCHEMA_EMPLOYMENT,
            &validity,
            &body_hash,
        );
        Ok(Claim {
            claim_id: ClaimId::from_signing_bytes(&signing),
            claim_type: ClaimType::Employment,
            schema_id: SCHEMA_EMPLOYMENT.to_string(),
            subject_id: subject.clone(),
            issuer_id: issuer.did(),
            validity,
            body,
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

    /// Verify this claim against the issuer's trusted key. On success returns a
    /// [`VerifiedClaim`] — the only way to read the body.
    pub fn verify(&self, issuer_vk: &VerifyingKey) -> Result<VerifiedClaim, ClaimReject> {
        if Did::from_key(issuer_vk) != self.issuer_id {
            return Err(ClaimReject::IssuerKeyMismatch);
        }
        let body_hash = hash_body(&self.body)?;
        if to_hex(&body_hash) != self.body_hash {
            return Err(ClaimReject::BodyTampered);
        }
        let signing = signing_bytes(
            &self.subject_id,
            &self.issuer_id,
            &self.claim_type,
            &self.schema_id,
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
    pub fn claim_type(&self) -> &ClaimType {
        &self.0.claim_type
    }
    pub fn validity(&self) -> &Validity {
        &self.0.validity
    }
    /// The trusted body — reachable only after verification.
    pub fn body(&self) -> &EmploymentBody {
        &self.0.body
    }
    pub fn active_at(&self, now: Timestamp) -> bool {
        self.0.validity.active_at(now)
    }
}

fn hash_body(body: &EmploymentBody) -> Result<[u8; 32], ClaimReject> {
    let bytes = serde_json::to_vec(body).map_err(|_| ClaimReject::Malformed)?;
    Ok(crypto::hash(&bytes))
}

fn signing_bytes(
    subject: &Did,
    issuer: &Did,
    claim_type: &ClaimType,
    schema: &str,
    validity: &Validity,
    body_hash: &[u8; 32],
) -> Vec<u8> {
    let mut w = SigningWriter::new(CLAIM_DOMAIN);
    w.field(subject.as_bytes())
        .field(issuer.as_bytes())
        .field(claim_type.tag())
        .field(schema.as_bytes())
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
    use aion_trust_core::Identity;

    fn body() -> EmploymentBody {
        EmploymentBody {
            employer: "Acme".into(),
            title: "Senior Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021-03-01".into(),
            end: None,
            rehire_eligible: true,
        }
    }

    #[test]
    fn claim_type_tag_is_stable() {
        assert_eq!(ClaimType::Employment.tag(), b"employment"); // kills tag -> empty/[0]/[1]
    }

    #[test]
    fn reject_messages_are_specific() {
        assert!(ClaimReject::BodyTampered.to_string().contains("body")); // kills Display -> default
        assert_ne!(
            ClaimReject::BadSignature.to_string(),
            ClaimReject::BodyTampered.to_string()
        );
    }

    #[test]
    fn validity_active_at_boundaries() {
        let v = Validity { from: Timestamp(10), until: Some(Timestamp(20)) };
        assert!(!v.active_at(Timestamp(9)));
        assert!(v.active_at(Timestamp(10)));
        assert!(v.active_at(Timestamp(20)));
        assert!(!v.active_at(Timestamp(21)));
        let open = Validity { from: Timestamp(10), until: None };
        assert!(open.active_at(Timestamp(1_000)));
        assert!(!open.active_at(Timestamp(9)));
    }

    #[test]
    fn signing_bytes_is_nonempty_and_binds_every_field() {
        let s = Did::from_string("did:aion:subject".into());
        let i = Did::from_string("did:aion:issuer".into());
        let v = Validity { from: Timestamp(1), until: None };
        let h = [7u8; 32];
        let base = signing_bytes(&s, &i, &ClaimType::Employment, "schema", &v, &h);
        assert!(!base.is_empty()); // kills signing_bytes -> vec![]
        let other = Did::from_string("did:aion:other".into());
        assert_ne!(base, signing_bytes(&other, &i, &ClaimType::Employment, "schema", &v, &h));
        assert_ne!(base, signing_bytes(&s, &other, &ClaimType::Employment, "schema", &v, &h));
        assert_ne!(base, signing_bytes(&s, &i, &ClaimType::Employment, "schema2", &v, &h));
        let v_from = Validity { from: Timestamp(2), until: None };
        assert_ne!(base, signing_bytes(&s, &i, &ClaimType::Employment, "schema", &v_from, &h));
        // open vs until-bounded must differ — pins the Some/None match arm
        let v_until = Validity { from: Timestamp(1), until: Some(Timestamp(9)) };
        assert_ne!(base, signing_bytes(&s, &i, &ClaimType::Employment, "schema", &v_until, &h));
        assert_ne!(base, signing_bytes(&s, &i, &ClaimType::Employment, "schema", &v, &[8u8; 32]));
    }

    #[test]
    fn issue_then_verify_exposes_the_body() {
        let issuer = Identity::generate();
        let subject = Did::from_string("did:aion:subj".into());
        let validity = Validity { from: Timestamp(0), until: None };
        let claim = Claim::issue(&issuer, &subject, validity, body()).unwrap();
        let verified = claim.verify(&issuer.verifying_key()).expect("verify");
        assert_eq!(verified.body().title, "Senior Engineer");
        assert_eq!(verified.subject_id(), &subject);
        assert_eq!(verified.claim_type(), &ClaimType::Employment);
    }
}
