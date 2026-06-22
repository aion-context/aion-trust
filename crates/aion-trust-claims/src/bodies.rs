//! The claim bodies and the [`ClaimBody`] sum type.
//!
//! Fusing the claim *category* and its *body* into one enum (rather than a separate
//! `ClaimType` tag beside a concrete body) makes the illegal combination —
//! "type says education, body is employment" — unrepresentable, and keeps the verifier
//! category-agnostic. Every body is plain, serializable PII; it lives only in the wallet
//! and in disclosed presentations, never on the ledger.

use serde::{Deserialize, Serialize};

/// "Senior Engineer at Acme, 2021–2024" — attested by a former employer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentBody {
    pub employer: String,
    pub title: String,
    pub employment_type: String,
    pub start: String,
    pub end: Option<String>,
    pub rehire_eligible: bool,
}

/// A degree — attested by the institution, optionally imported from an aion-edu diploma.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EducationBody {
    pub institution: String,
    pub credential: String,
    pub conferred: String,
    /// Content hash of the originating aion-edu sealed diploma, if imported.
    pub aion_edu_ref: Option<String>,
    /// An **issuer-attested** ordinal level on the scale pinned by this category's `schema_id`
    /// (0 none · 1 secondary · 2 associate · 3 bachelor · 4 master · 5 doctorate). It exists so
    /// a subject can answer "degree ≥ bachelor's" by disclosing only this coarse rank, without
    /// the exact `credential`. The verifier never derives a rank from free text — it trusts
    /// only this signed value (see [`crate::predicate`]).
    pub degree_rank: Option<u8>,
}

/// A professional certification / license — attested by the certifying authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationBody {
    pub authority: String,
    pub name: String,
    pub issued: String,
    pub expires: Option<String>,
    pub credential_no: Option<String>,
}

/// The reusable, money-saving claim — attested by an accredited screening provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCheckBody {
    pub provider: String,
    pub scope: Vec<String>,
    pub result: String,
    pub performed: String,
    pub valid_until: Option<String>,
    pub jurisdiction: String,
    pub fcra_compliant: bool,
}

/// KYC / right-to-work — attested by an accredited identity provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBody {
    pub method: String,
    pub verified: String,
    pub assurance: String,
}

/// A named reference's attestation (the referee is itself an issuer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceBody {
    pub relationship: String,
    pub statement_hash: String,
    pub given: String,
}

/// A skill — self-asserted, optionally with an assessed level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillBody {
    pub skill: String,
    pub level: Option<String>,
}

/// Every kind of claim body. Internally tagged, so a claim's JSON carries
/// `"claim_type": "<category>"` alongside the body fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_type", rename_all = "snake_case")]
pub enum ClaimBody {
    Employment(EmploymentBody),
    Education(EducationBody),
    Certification(CertificationBody),
    BackgroundCheck(BackgroundCheckBody),
    Identity(IdentityBody),
    Reference(ReferenceBody),
    Skill(SkillBody),
}

impl ClaimBody {
    /// The claim category — the wire tag and (in Phase 3) the accreditation key.
    pub fn category(&self) -> &'static str {
        match self {
            ClaimBody::Employment(_) => "employment",
            ClaimBody::Education(_) => "education",
            ClaimBody::Certification(_) => "certification",
            ClaimBody::BackgroundCheck(_) => "background_check",
            ClaimBody::Identity(_) => "identity",
            ClaimBody::Reference(_) => "reference",
            ClaimBody::Skill(_) => "skill",
        }
    }

    /// The canonical field-key set for a category, in JCS (sorted) order — derived from the
    /// body type, not a registry. A verifier knows the category (a signed scalar), so it knows
    /// exactly which fields a claim has and can detect a maliciously *omitted* field and check
    /// that each disclosed field's key matches the expected key at its leaf index. Returns
    /// `None` for an unknown category. Kept in lockstep with the actual serialization by the
    /// `field_keys_match_serialization` gate test.
    pub fn field_keys_for_category(category: &str) -> Option<&'static [&'static str]> {
        let keys: &'static [&'static str] = match category {
            "employment" => &[
                "employer",
                "employment_type",
                "end",
                "rehire_eligible",
                "start",
                "title",
            ],
            "education" => &[
                "aion_edu_ref",
                "conferred",
                "credential",
                "degree_rank",
                "institution",
            ],
            "certification" => &["authority", "credential_no", "expires", "issued", "name"],
            "background_check" => &[
                "fcra_compliant",
                "jurisdiction",
                "performed",
                "provider",
                "result",
                "scope",
                "valid_until",
            ],
            "identity" => &["assurance", "method", "verified"],
            "reference" => &["given", "relationship", "statement_hash"],
            "skill" => &["level", "skill"],
            _ => return None,
        };
        Some(keys)
    }

    /// The versioned schema id for this category — signed, so the version can't be tampered.
    pub fn schema_id(&self) -> &'static str {
        match self {
            ClaimBody::Employment(_) => "aion-trust/employment/v1",
            ClaimBody::Education(_) => "aion-trust/education/v1",
            ClaimBody::Certification(_) => "aion-trust/certification/v1",
            ClaimBody::BackgroundCheck(_) => "aion-trust/background_check/v1",
            ClaimBody::Identity(_) => "aion-trust/identity/v1",
            ClaimBody::Reference(_) => "aion-trust/reference/v1",
            ClaimBody::Skill(_) => "aion-trust/skill/v1",
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn one_of_each() -> Vec<(ClaimBody, &'static str, &'static str)> {
        let s = String::new;
        vec![
            (
                ClaimBody::Employment(EmploymentBody {
                    employer: s(),
                    title: s(),
                    employment_type: s(),
                    start: s(),
                    end: None,
                    rehire_eligible: false,
                }),
                "employment",
                "aion-trust/employment/v1",
            ),
            (
                ClaimBody::Education(EducationBody {
                    institution: s(),
                    credential: s(),
                    conferred: s(),
                    aion_edu_ref: None,
                    degree_rank: None,
                }),
                "education",
                "aion-trust/education/v1",
            ),
            (
                ClaimBody::Certification(CertificationBody {
                    authority: s(),
                    name: s(),
                    issued: s(),
                    expires: None,
                    credential_no: None,
                }),
                "certification",
                "aion-trust/certification/v1",
            ),
            (
                ClaimBody::BackgroundCheck(BackgroundCheckBody {
                    provider: s(),
                    scope: vec![],
                    result: s(),
                    performed: s(),
                    valid_until: None,
                    jurisdiction: s(),
                    fcra_compliant: false,
                }),
                "background_check",
                "aion-trust/background_check/v1",
            ),
            (
                ClaimBody::Identity(IdentityBody {
                    method: s(),
                    verified: s(),
                    assurance: s(),
                }),
                "identity",
                "aion-trust/identity/v1",
            ),
            (
                ClaimBody::Reference(ReferenceBody {
                    relationship: s(),
                    statement_hash: s(),
                    given: s(),
                }),
                "reference",
                "aion-trust/reference/v1",
            ),
            (
                ClaimBody::Skill(SkillBody {
                    skill: s(),
                    level: None,
                }),
                "skill",
                "aion-trust/skill/v1",
            ),
        ]
    }

    #[test]
    fn every_variant_has_its_own_category_and_schema() {
        for (body, category, schema) in one_of_each() {
            assert_eq!(body.category(), category);
            assert_eq!(body.schema_id(), schema);
            // the wire tag (serde) must match the category
            let json = serde_json::to_value(&body).unwrap();
            assert_eq!(json["claim_type"], category);
        }
    }

    #[test]
    fn field_keys_known_for_every_category_and_sorted() {
        for (body, category, _) in one_of_each() {
            let keys = ClaimBody::field_keys_for_category(category)
                .unwrap_or_else(|| panic!("no field keys for {category}"));
            assert!(!keys.is_empty());
            // declared in JCS (sorted) order
            let mut sorted = keys.to_vec();
            sorted.sort_unstable();
            assert_eq!(keys.to_vec(), sorted, "{category} keys not sorted");
            // the type tag is never a disclosable field
            assert!(!keys.contains(&"claim_type"));
            let _ = body; // body only used to enumerate categories
        }
        assert!(ClaimBody::field_keys_for_category("nonsense").is_none());
    }
}
