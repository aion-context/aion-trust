//! The [`Claim`]: an issuer's signed attestation about a subject, with a verify-before-trust
//! typestate. The PII-bearing [`ClaimBody`] is private; only a [`VerifiedClaim`] — produced
//! solely by a successful signature check — exposes it. The category and schema are functions
//! of the body, so a claim cannot mislabel its own type.

use aion_context::crypto::VerifyingKey;
use aion_trust_core::encoding::{decode_array, to_hex, SigningWriter};
use aion_trust_core::merkle::merkle_root;
use aion_trust_core::{ClaimId, Did, Identity, Timestamp};
use serde::{Deserialize, Serialize};

use crate::bodies::ClaimBody;
use crate::disclosure::{DisclosedClaim, FieldSelector};
use crate::fields::body_leaves;

pub const CLAIM_DOMAIN: &[u8] = b"aion-trust/claim/v1";

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
    /// A disclosure withheld a field the verifier requires (omission detection).
    MissingField,
    Malformed,
}

impl std::fmt::Display for ClaimReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ClaimReject::IssuerKeyMismatch => "issuer key does not match issuer_id",
            ClaimReject::BodyTampered => "field does not match the signed body_root",
            ClaimReject::ClaimIdMismatch => "claim_id does not match signed content",
            ClaimReject::BadSignature => "issuer signature is invalid",
            ClaimReject::MissingField => "a required field was not disclosed",
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
    /// Random 32-byte per-claim master salt. Lives with the claim in the wallet, never on the
    /// ledger. Every field's leaf salt is *derived* from it (see [`crate::fields`]), so the
    /// `body_root` is a *hiding* commitment over low-entropy PII, and disclosing one field's
    /// salt reveals nothing about the withheld fields.
    pub master_salt: String,
    /// Merkle root over the body's salted field leaves. The issuer signs this, so a subject
    /// can later disclose a subset of fields and still prove them against it.
    pub body_root: String,
    /// Number of field leaves in the tree. Signed, so the tree's shape cannot be altered.
    pub field_count: u32,
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
        let master_salt = random_salt();
        let (body_root, field_count) = body_commitment(&master_salt, &body)?;
        let signing = signing_bytes(
            subject,
            &issuer.did(),
            body.category(),
            body.schema_id(),
            &validity,
            &body_root,
            field_count,
        );
        Ok(Claim {
            claim_id: ClaimId::from_signing_bytes(&signing),
            subject_id: subject.clone(),
            issuer_id: issuer.did(),
            validity,
            body,
            master_salt: to_hex(&master_salt),
            body_root: to_hex(&body_root),
            field_count,
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

    /// The versioned schema id — safe to read pre-verification; it does not expose the body.
    pub fn schema_id(&self) -> &'static str {
        self.body.schema_id()
    }

    /// Read one body field by key — **holder-side introspection only**, for a wallet choosing
    /// which field to disclose for a predicate. This is the subject reading their own claim;
    /// it is not a verification path and grants no trust (a verifier still reads fields only
    /// through a [`crate::VerifiedDisclosure`]). Returns `None` for an unknown key.
    pub fn field_value(&self, key: &str) -> Option<serde_json::Value> {
        let serde_json::Value::Object(mut map) = serde_json::to_value(&self.body).ok()? else {
            return None;
        };
        map.remove(key)
    }

    /// Derive a [`DisclosedClaim`] revealing the fields named by `selector` (all, by default).
    /// This is the only method that reads the private body to build disclosures, so the wallet
    /// stays the sole place PII leaves storage. The undisclosed fields contribute only sibling
    /// hashes to the proofs; their values never appear in the result.
    pub fn disclose(&self, selector: &FieldSelector) -> Result<DisclosedClaim, ClaimReject> {
        let master_salt =
            decode_array::<32>(&self.master_salt).map_err(|_| ClaimReject::Malformed)?;
        let leaves = body_leaves(&master_salt, &self.body)?;
        DisclosedClaim::build(self, &leaves, selector)
    }

    /// Verify this claim against the issuer's trusted key. On success returns a
    /// [`VerifiedClaim`] — the only way to read the body.
    pub fn verify(&self, issuer_vk: &VerifyingKey) -> Result<VerifiedClaim, ClaimReject> {
        if Did::from_key(issuer_vk) != self.issuer_id {
            return Err(ClaimReject::IssuerKeyMismatch);
        }
        let master_salt =
            decode_array::<32>(&self.master_salt).map_err(|_| ClaimReject::Malformed)?;
        let (body_root, field_count) = body_commitment(&master_salt, &self.body)?;
        if to_hex(&body_root) != self.body_root || field_count != self.field_count {
            return Err(ClaimReject::BodyTampered);
        }
        let signing = signing_bytes(
            &self.subject_id,
            &self.issuer_id,
            self.body.category(),
            self.body.schema_id(),
            &self.validity,
            &body_root,
            field_count,
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
#[must_use = "a verified claim carries a trust decision; dropping it discards the check"]
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

/// Draw a fresh 32-byte master salt. `aion-context` exposes only a 12-byte nonce generator, so
/// we compose three CSPRNG draws through its BLAKE3 — composition of an existing CSPRNG, not
/// new cryptography.
fn random_salt() -> [u8; 32] {
    let mut seed = Vec::with_capacity(36);
    for _ in 0..3 {
        seed.extend_from_slice(&aion_context::crypto::generate_nonce());
    }
    aion_context::crypto::hash(&seed)
}

/// Commit a body as a Merkle root over its salted field leaves, returning the root and the
/// leaf count. Canonical (JCS) and salted (hiding) per field — the foundation that lets a
/// subject later disclose a subset of fields and still prove them against the signed root.
fn body_commitment(
    master_salt: &[u8; 32],
    body: &ClaimBody,
) -> Result<([u8; 32], u32), ClaimReject> {
    let leaves = body_leaves(master_salt, body)?;
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
    let root = merkle_root(&hashes).map_err(|_| ClaimReject::Malformed)?;
    let count = u32::try_from(hashes.len()).map_err(|_| ClaimReject::Malformed)?;
    Ok((root, count))
}

/// The issuer-signed message. Binds the body only through `category`, `schema_id`, `body_root`,
/// and `field_count` — never the body bytes — so a verifier can reconstruct it from a
/// disclosed claim that carries no body. `field_count` pins the tree's shape.
pub(crate) fn signing_bytes(
    subject: &Did,
    issuer: &Did,
    category: &str,
    schema_id: &str,
    validity: &Validity,
    body_root: &[u8; 32],
    field_count: u32,
) -> Vec<u8> {
    let mut w = SigningWriter::new(CLAIM_DOMAIN);
    w.field(subject.as_bytes())
        .field(issuer.as_bytes())
        .field(category.as_bytes())
        .field(schema_id.as_bytes())
        .int(validity.from.0);
    match validity.until {
        Some(t) => {
            w.field(b"until").int(t.0);
        }
        None => {
            w.field(b"open");
        }
    }
    w.field(body_root).u32(field_count);
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
    fn body_commitment_binds_salt_body_and_count() {
        let b = employment();
        let (root, count) = body_commitment(&[1u8; 32], &b).unwrap();
        assert_eq!(count, 6); // employment has six fields
                              // a different master salt → different root (hiding)
        assert_ne!(root, body_commitment(&[2u8; 32], &b).unwrap().0);
        // different body content → different root, and a different field count
        let other = ClaimBody::Skill(SkillBody {
            skill: "Rust".into(),
            level: None,
        });
        let (other_root, other_count) = body_commitment(&[1u8; 32], &other).unwrap();
        assert_ne!(root, other_root);
        assert_eq!(other_count, 2);
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
        let base = signing_bytes(&s, &i, "employment", "schema/v1", &v, &h, 6);
        assert!(!base.is_empty());
        let other = Did::from_string("did:aion:other".into());
        assert_ne!(
            base,
            signing_bytes(&other, &i, "employment", "schema/v1", &v, &h, 6)
        );
        assert_ne!(
            base,
            signing_bytes(&s, &other, "employment", "schema/v1", &v, &h, 6)
        );
        assert_ne!(base, signing_bytes(&s, &i, "skill", "schema/v1", &v, &h, 6)); // category
        assert_ne!(
            base,
            signing_bytes(&s, &i, "employment", "schema/v2", &v, &h, 6)
        ); // schema
        let v_from = Validity {
            from: Timestamp(2),
            until: None,
        };
        assert_ne!(
            base,
            signing_bytes(&s, &i, "employment", "schema/v1", &v_from, &h, 6)
        );
        let v_until = Validity {
            from: Timestamp(1),
            until: Some(Timestamp(9)),
        };
        // open vs until arm
        assert_ne!(
            base,
            signing_bytes(&s, &i, "employment", "schema/v1", &v_until, &h, 6)
        );
        assert_ne!(
            base,
            signing_bytes(&s, &i, "employment", "schema/v1", &v, &[8u8; 32], 6)
        ); // root
        assert_ne!(
            base,
            signing_bytes(&s, &i, "employment", "schema/v1", &v, &h, 7)
        ); // field_count
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
        assert_eq!(claim.schema_id(), "aion-trust/employment/v1");
        let verified = claim.verify(&issuer.verifying_key()).expect("verify");
        assert_eq!(verified.subject_id(), &subject);
        assert_eq!(verified.category(), "employment");
        match verified.body() {
            ClaimBody::Employment(e) => assert_eq!(e.title, "Senior Engineer"),
            _ => panic!("wrong body"),
        }
    }

    fn issued() -> (Identity, Claim) {
        let issuer = Identity::generate();
        let subject = Did::from_string("did:aion:subj".into());
        let validity = Validity {
            from: Timestamp(10),
            until: Some(Timestamp(20)),
        };
        let claim = Claim::issue(&issuer, &subject, validity, employment()).unwrap();
        (issuer, claim)
    }

    #[test]
    fn field_value_reads_body_fields_for_path_finding() {
        let (_, claim) = issued();
        assert_eq!(
            claim.field_value("title"),
            Some(serde_json::json!("Senior Engineer"))
        );
        assert_eq!(claim.field_value("nope"), None);
    }

    #[test]
    fn tampered_field_count_alone_is_rejected() {
        // body_root still matches but the (signed) field_count was altered → BodyTampered.
        // Pins the `||` in verify: an `&&` mutant would miss a count-only tamper.
        let (issuer, claim) = issued();
        let mut v = serde_json::to_value(&claim).unwrap();
        v["field_count"] = serde_json::json!(claim.field_count + 1);
        let tampered: Claim = serde_json::from_value(v).unwrap();
        assert_eq!(
            tampered.verify(&issuer.verifying_key()).err(),
            Some(ClaimReject::BodyTampered)
        );
    }

    #[test]
    fn verified_claim_active_at_follows_validity() {
        let (issuer, claim) = issued(); // validity 10..=20
        let verified = claim.verify(&issuer.verifying_key()).unwrap();
        assert!(verified.active_at(Timestamp(15)));
        assert!(!verified.active_at(Timestamp(25)));
    }
}
