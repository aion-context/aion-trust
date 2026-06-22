//! `DisclosedClaim` ↔ W3C Verifiable Credential (JSON-LD data model), native proof preserved.
//!
//! Export maps the disclosure onto a VC envelope and carries aion-trust's Ed25519 signature +
//! the Merkle disclosure inside a vendor-namespaced `proof`. Import is **verify-then-read**: it
//! rebuilds the native `DisclosedClaim` from the *proof* (not the human-readable
//! `credentialSubject`), checks the `did:key`↔`did:aion` binding, runs `DisclosedClaim::verify`,
//! and returns the artifact only if it cryptographically verifies.

use aion_context::crypto::VerifyingKey;
use aion_trust_claims::DisclosedClaim;
use aion_trust_core::Did;
use serde_json::{json, Value};

use crate::didkey::{decode_did_key, verification_method};
use crate::error::{InteropError, Result};
use crate::jsonget::{get_obj, get_str, take};
use crate::rfc3339::{from_rfc3339, to_rfc3339};
use crate::{CONTEXT_V1, PROOF_TYPE, SCHEMA_BASE};

/// Export a disclosure as a Verifiable Credential. `issuer_vk` is the issuer's public key
/// (resolved by the caller from the registry; a `DisclosedClaim` carries only the one-way
/// `did:aion`). Never accepts a full `Claim`, so `master_salt` cannot escape.
pub fn export_disclosed_vc(d: &DisclosedClaim, issuer_vk: &VerifyingKey) -> Result<Value> {
    let native = serde_json::to_value(d)?; // DisclosedClaim's own serde shape
    let subject_id = get_str(&native, "subject_id")?;
    let category = get_str(&native, "category")?;
    let schema_id = get_str(&native, "schema_id")?;
    let validity = get_obj(&native, "validity")?;
    let fields = native
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(InteropError::WrongType("fields"))?;

    let mut subject = serde_json::Map::new();
    subject.insert("id".into(), json!(subject_id));
    for f in fields {
        subject.insert(get_str(f, "key")?.to_string(), take(f, "value")?.clone());
    }

    let vm = verification_method(issuer_vk);
    let proof = json!({
        "type": PROOF_TYPE,
        "proofPurpose": "assertionMethod",
        "verificationMethod": vm,
        "category": category,
        "schemaId": schema_id,
        "bodyRoot": get_str(&native, "body_root")?,
        "fieldCount": take(&native, "field_count")?,
        "aionSignature": get_str(&native, "issuer_signature")?,
        "disclosures": fields,
    });

    let mut vc = json!({
        "@context": CONTEXT_V1,
        "type": ["VerifiableCredential", category_to_vc_type(category)],
        "id": format!("urn:aion-trust:claim:{}", get_str(&native, "claim_id")?),
        "issuer": get_str(&native, "issuer_id")?,
        "credentialSchema": { "id": format!("{SCHEMA_BASE}{schema_id}"), "type": "AionTrustSchema2026" },
        "validFrom": to_rfc3339(validity_ts(validity, "from")?),
        "credentialSubject": Value::Object(subject),
        "proof": proof,
    });
    if let Some(until) = validity.get("until").filter(|u| !u.is_null()) {
        let until = until.as_i64().ok_or(InteropError::WrongType("until"))?;
        vc["validUntil"] = json!(to_rfc3339(aion_trust_core::Timestamp(until)));
    }
    Ok(vc)
}

/// Import a VC back into a `DisclosedClaim` — reconstructs from the proof, enforces the
/// `did:key`↔`did:aion` binding, and re-verifies. Returns the verified disclosure or an error.
pub fn import_disclosed_vc(doc: &Value) -> Result<DisclosedClaim> {
    let proof = get_obj(doc, "proof")?;
    let issuer_vk = decode_did_key(get_str(proof, "verificationMethod")?)?;
    let native = rebuild_native(doc, proof)?;
    let disclosed: DisclosedClaim = serde_json::from_value(native)?;

    // MUST: the did:key public key must derive the did:aion the document claims (no key swap).
    let derived = Did::from_key(&issuer_vk);
    if &derived != disclosed.issuer_id() {
        return Err(InteropError::DidBinding {
            expected: disclosed.issuer_id().as_str().to_string(),
            derived: derived.as_str().to_string(),
        });
    }
    // Verify-then-trust: aion-trust's own check (signature + every field's Merkle proof). The
    // VerifiedDisclosure is discarded — we return the wire type, having proven it verifies.
    let _verified = disclosed
        .verify(&issuer_vk)
        .map_err(|e| InteropError::Verify(e.to_string()))?;
    Ok(disclosed)
}

/// Rebuild the `DisclosedClaim`'s native serde JSON from the VC's proof-carried fields. The
/// human-readable `credentialSubject` is NOT consulted — only the proof is authoritative. The
/// top-level `id`/`issuer`/`validFrom`/`validUntil` ARE read here, but all of them feed
/// `signing_bytes`, so a forged value changes the reconstruction and fails `verify` downstream.
fn rebuild_native(doc: &Value, proof: &Value) -> Result<Value> {
    let id = get_str(doc, "id")?;
    let claim_id = id
        .strip_prefix("urn:aion-trust:claim:")
        .ok_or(InteropError::WrongType("id"))?;
    let validity = json!({
        "from": from_rfc3339(get_str(doc, "validFrom")?)?.0,
        "until": match doc.get("validUntil") {
            Some(v) if !v.is_null() => json!(from_rfc3339(v.as_str().ok_or(InteropError::WrongType("validUntil"))?)?.0),
            _ => Value::Null,
        },
    });
    Ok(json!({
        "claim_id": claim_id,
        "subject_id": subject_did(doc)?,
        "issuer_id": get_str(doc, "issuer")?,
        "validity": validity,
        "category": get_str(proof, "category")?,
        "schema_id": get_str(proof, "schemaId")?,
        "body_root": get_str(proof, "bodyRoot")?,
        "field_count": take(proof, "fieldCount")?,
        "issuer_signature": get_str(proof, "aionSignature")?,
        "fields": take(proof, "disclosures")?,
    }))
}

fn subject_did(doc: &Value) -> Result<String> {
    Ok(get_str(get_obj(doc, "credentialSubject")?, "id")?.to_string())
}

fn validity_ts(validity: &Value, key: &'static str) -> Result<aion_trust_core::Timestamp> {
    let n = validity
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(InteropError::WrongType(key))?;
    Ok(aion_trust_core::Timestamp(n))
}

/// Map an aion-trust category to a VC credential type. Pure and total.
pub(crate) fn category_to_vc_type(category: &str) -> &'static str {
    match category {
        "employment" => "EmploymentCredential",
        "education" => "EducationCredential",
        "background_check" => "BackgroundCheckCredential",
        "certification" => "CertificationCredential",
        "identity" => "IdentityCredential",
        "reference" => "ReferenceCredential",
        "skill" => "SkillCredential",
        _ => "AionTrustCredential",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_claims::{Claim, ClaimBody, EmploymentBody, FieldSelector, Validity};
    use aion_trust_core::{Identity, Timestamp};

    fn issued() -> (Identity, Claim) {
        let issuer = Identity::generate();
        let subject = Identity::generate().did();
        let body = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Senior Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021-03-01".into(),
            end: Some("2024-08-15".into()),
            rehire_eligible: true,
        });
        let validity = Validity {
            from: Timestamp(1_614_556_800), // 2021-03-01
            until: None,
        };
        let claim = Claim::issue(&issuer, &subject, validity, body).unwrap();
        (issuer, claim)
    }

    fn disclose(claim: &Claim, keys: &[&str]) -> DisclosedClaim {
        let sel = FieldSelector::Only(keys.iter().map(|s| s.to_string()).collect());
        claim.disclose(&sel).unwrap()
    }

    #[test]
    fn category_type_is_total() {
        for (cat, ty) in [
            ("employment", "EmploymentCredential"),
            ("education", "EducationCredential"),
            ("background_check", "BackgroundCheckCredential"),
            ("certification", "CertificationCredential"),
            ("identity", "IdentityCredential"),
            ("reference", "ReferenceCredential"),
            ("skill", "SkillCredential"),
        ] {
            assert_eq!(category_to_vc_type(cat), ty);
        }
        assert_eq!(category_to_vc_type("nonsense"), "AionTrustCredential");
    }

    #[test]
    fn export_has_w3c_envelope_and_native_proof() {
        let (issuer, claim) = issued();
        let d = disclose(&claim, &["employer", "title"]);
        let vc = export_disclosed_vc(&d, &issuer.verifying_key()).unwrap();
        assert_eq!(vc["type"][0], "VerifiableCredential");
        assert_eq!(vc["type"][1], "EmploymentCredential");
        assert_eq!(vc["proof"]["type"], PROOF_TYPE); // NOT a Data-Integrity suite
        assert!(vc["proof"]["verificationMethod"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z"));
        assert_eq!(vc["issuer"], json!(d.issuer_id().as_str()));
        assert_eq!(vc["credentialSubject"]["title"], "Senior Engineer");
        assert!(vc.get("validUntil").is_none()); // until=None omitted
                                                 // master_salt must never appear anywhere in the exported artifact
        assert!(!vc.to_string().contains("master_salt"));
        assert!(!vc.to_string().contains(&claim.master_salt));
    }

    #[test]
    fn round_trip_imports_and_verifies() {
        let (issuer, claim) = issued();
        let d = disclose(&claim, &["employer", "title"]);
        let vc = export_disclosed_vc(&d, &issuer.verifying_key()).unwrap();
        let back = import_disclosed_vc(&vc).unwrap();
        assert_eq!(back.claim_id(), d.claim_id());
        let keys: Vec<&str> = back.disclosed_keys().collect();
        assert_eq!(keys, ["employer", "title"]);
        // it re-verifies against the embedded did:key
        assert!(back.verify(&issuer.verifying_key()).is_ok());
    }

    #[test]
    fn tampered_disclosed_value_is_rejected_on_import() {
        let (issuer, claim) = issued();
        let d = disclose(&claim, &["title"]);
        let mut vc = export_disclosed_vc(&d, &issuer.verifying_key()).unwrap();
        vc["proof"]["disclosures"][0]["value"] = json!("Chief Executive Officer");
        let err = import_disclosed_vc(&vc).unwrap_err();
        assert!(matches!(err, InteropError::Verify(_)));
    }

    #[test]
    fn substituted_verification_method_key_is_rejected() {
        let (issuer, claim) = issued();
        let d = disclose(&claim, &["title"]);
        let mut vc = export_disclosed_vc(&d, &issuer.verifying_key()).unwrap();
        // swap in a did:key for a DIFFERENT key that does not derive the claimed issuer
        let mallory = Identity::generate();
        vc["proof"]["verificationMethod"] = json!(verification_method(&mallory.verifying_key()));
        assert!(matches!(
            import_disclosed_vc(&vc),
            Err(InteropError::DidBinding { .. })
        ));
    }

    #[test]
    fn import_vc_without_proof_is_missing_field() {
        let (issuer, claim) = issued();
        let mut vc =
            export_disclosed_vc(&disclose(&claim, &["title"]), &issuer.verifying_key()).unwrap();
        vc.as_object_mut().unwrap().remove("proof");
        assert!(matches!(
            import_disclosed_vc(&vc),
            Err(InteropError::MissingField("proof"))
        ));
    }

    #[test]
    fn import_vc_rejects_non_urn_id() {
        let (issuer, claim) = issued();
        let mut vc =
            export_disclosed_vc(&disclose(&claim, &["title"]), &issuer.verifying_key()).unwrap();
        vc["id"] = json!("https://example.com/not-a-urn");
        assert!(matches!(
            import_disclosed_vc(&vc),
            Err(InteropError::WrongType("id"))
        ));
    }

    #[test]
    fn round_trips_with_valid_until_present() {
        // The until=Some path: validUntil is emitted, round-trips, and re-verifies.
        let issuer = Identity::generate();
        let subject = Identity::generate().did();
        let body = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021-03-01".into(),
            end: None,
            rehire_eligible: true,
        });
        let validity = Validity {
            from: Timestamp(1_614_556_800),
            until: Some(Timestamp(1_735_689_600)), // 2025-01-01
        };
        let claim = Claim::issue(&issuer, &subject, validity, body).unwrap();
        let d = disclose(&claim, &["title"]);
        let vc = export_disclosed_vc(&d, &issuer.verifying_key()).unwrap();
        assert_eq!(vc["validUntil"], "2025-01-01T00:00:00Z");
        let back = import_disclosed_vc(&vc).unwrap();
        assert!(back.verify(&issuer.verifying_key()).is_ok());
        assert_eq!(back.claim_id(), d.claim_id());
    }

    #[test]
    fn import_vc_rejects_non_string_valid_until() {
        let issuer = Identity::generate();
        let subject = Identity::generate().did();
        let body = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021".into(),
            end: None,
            rehire_eligible: true,
        });
        let claim = Claim::issue(
            &issuer,
            &subject,
            Validity {
                from: Timestamp(0),
                until: Some(Timestamp(1_000_000)),
            },
            body,
        )
        .unwrap();
        let mut vc =
            export_disclosed_vc(&disclose(&claim, &["title"]), &issuer.verifying_key()).unwrap();
        vc["validUntil"] = json!(12345); // not a string
        assert!(matches!(
            import_disclosed_vc(&vc),
            Err(InteropError::WrongType("validUntil"))
        ));
    }
}
