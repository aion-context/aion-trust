//! `Presentation` ↔ W3C Verifiable Presentation, native proof preserved.
//!
//! The VP's holder binding is **self-contained**: the subject's public key travels in
//! `proof.verificationMethod` (derived from the Presentation's `subject_key`). Each embedded
//! credential still needs the issuer's key, which a `DisclosedClaim` lacks (only `did:aion`), so
//! export takes an issuer-key resolver. Import rebuilds the native `Presentation`, verifies every
//! embedded credential (via [`crate::import_disclosed_vc`]) and the holder binding; final
//! whole-presentation verification (audience, nonce single-use, expiry) is the caller's
//! `verify_presentation` against its own trust anchor.

use aion_context::crypto::VerifyingKey;
use aion_trust_claims::Presentation;
use aion_trust_core::identity::verifying_key_from_hex;
use aion_trust_core::{encoding::to_hex, Did};
use serde_json::{json, Value};

use crate::didkey::{decode_did_key, verification_method};
use crate::error::{InteropError, Result};
use crate::jsonget::{get_obj, get_str};
use crate::rfc3339::{from_rfc3339, to_rfc3339};
use crate::vc::{export_disclosed_vc, import_disclosed_vc};
use crate::{CONTEXT_V1, PROOF_TYPE};

/// Export a presentation as a Verifiable Presentation. `resolve_issuer` maps each embedded
/// claim's `did:aion` issuer to its public key (the caller wires the registry).
pub fn export_presentation_vp(
    p: &Presentation,
    resolve_issuer: &dyn Fn(&Did) -> Option<VerifyingKey>,
) -> Result<Value> {
    let mut vcs = Vec::with_capacity(p.claims.len());
    for claim in &p.claims {
        let vk = resolve_issuer(claim.issuer_id()).ok_or_else(|| {
            InteropError::UnresolvedIssuer(claim.issuer_id().as_str().to_string())
        })?;
        vcs.push(export_disclosed_vc(claim, &vk)?);
    }
    let subject_vk = verifying_key_from_hex(&p.subject_key)?;
    let proof = json!({
        "type": PROOF_TYPE,
        "proofPurpose": "authentication",
        "verificationMethod": verification_method(&subject_vk),
        "domain": p.audience.as_str(),
        "challenge": p.nonce,
        "purpose": p.purpose,
        "issuedAt": to_rfc3339(p.issued_at),
        "expiresAt": to_rfc3339(p.expires_at),
        "aionSignature": p.subject_signature,
    });
    Ok(json!({
        "@context": CONTEXT_V1,
        "type": ["VerifiablePresentation"],
        "id": format!("urn:aion-trust:presentation:{}", p.presentation_id),
        "holder": p.subject_id.as_str(),
        "verifiableCredential": vcs,
        "proof": proof,
    }))
}

/// Import a VP back into a `Presentation` — verifies every embedded credential and the holder
/// `did:key`↔`did:aion` binding. Whole-presentation verification (audience/nonce/expiry) is the
/// caller's `verify_presentation`.
pub fn import_presentation_vp(doc: &Value) -> Result<Presentation> {
    let proof = get_obj(doc, "proof")?;
    let subject_vk = decode_did_key(get_str(proof, "verificationMethod")?)?;
    let holder = get_str(doc, "holder")?;

    // MUST: the holder did:key must derive the holder did:aion (no key swap).
    let derived = Did::from_key(&subject_vk);
    if derived.as_str() != holder {
        return Err(InteropError::DidBinding {
            expected: holder.to_string(),
            derived: derived.as_str().to_string(),
        });
    }

    // Verify and re-serialize each embedded credential to its native DisclosedClaim shape.
    let vcs = doc
        .get("verifiableCredential")
        .and_then(Value::as_array)
        .ok_or(InteropError::WrongType("verifiableCredential"))?;
    let mut claims = Vec::with_capacity(vcs.len());
    for vc in vcs {
        claims.push(serde_json::to_value(import_disclosed_vc(vc)?)?);
    }

    let id = get_str(doc, "id")?;
    let presentation_id = id
        .strip_prefix("urn:aion-trust:presentation:")
        .ok_or(InteropError::WrongType("id"))?;
    let native = json!({
        "presentation_id": presentation_id,
        "subject_id": holder,
        "subject_key": to_hex(&subject_vk.to_bytes()),
        "audience": get_str(proof, "domain")?,
        "purpose": get_str(proof, "purpose")?,
        "nonce": get_str(proof, "challenge")?,
        "issued_at": from_rfc3339(get_str(proof, "issuedAt")?)?.0,
        "expires_at": from_rfc3339(get_str(proof, "expiresAt")?)?.0,
        "claims": claims,
        "subject_signature": get_str(proof, "aionSignature")?,
    });
    Ok(serde_json::from_value(native)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_claims::{
        build_presentation, verify_presentation, Claim, ClaimBody, EmploymentBody, FieldSelector,
        IssuerDirectory, Validity,
    };
    use aion_trust_core::{Identity, Timestamp};

    fn world() -> (Identity, Identity, Did, Presentation, IssuerDirectory) {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let audience = Identity::generate().did();
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
            &subject.did(),
            Validity {
                from: Timestamp(0),
                until: None,
            },
            body,
        )
        .unwrap();
        let d = claim
            .disclose(&FieldSelector::Only(vec![
                "employer".into(),
                "title".into(),
            ]))
            .unwrap();
        let p = build_presentation(
            &subject,
            &audience,
            "application",
            b"nonce-abcdef012345",
            Timestamp(100),
            Timestamp(10_000),
            vec![d],
        );
        let mut dir = IssuerDirectory::new();
        dir.register(issuer.verifying_key());
        (issuer, subject, audience, p, dir)
    }

    #[test]
    fn vp_round_trips_and_still_verifies() {
        let (issuer, _subject, audience, p, dir) = world();
        let vk = issuer.verifying_key();
        let resolver = |_did: &Did| Some(vk);
        let vp = export_presentation_vp(&p, &resolver).unwrap();
        assert_eq!(vp["type"][0], "VerifiablePresentation");
        assert_eq!(vp["proof"]["type"], PROOF_TYPE);
        assert!(vp["proof"]["verificationMethod"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z"));

        // no wallet secret escapes in the VP (the embedded VCs carry only per-field salts)
        assert!(!vp.to_string().contains("master_salt"));

        let back = import_presentation_vp(&vp).unwrap();
        // the reconstructed presentation verifies offline against the registry
        let report = verify_presentation(&back, &audience, Timestamp(200), &dir, false).unwrap();
        assert!(report.accepted, "checks: {:?}", report.checks);
    }

    #[test]
    fn import_vp_rejects_non_urn_id() {
        let (issuer, _s, _a, p, _dir) = world();
        let vk = issuer.verifying_key();
        let mut vp = export_presentation_vp(&p, &|_d| Some(vk)).unwrap();
        vp["id"] = json!("https://example.com/not-a-urn");
        assert!(matches!(
            import_presentation_vp(&vp),
            Err(InteropError::WrongType("id"))
        ));
    }

    #[test]
    fn import_vp_rejects_missing_credentials_field() {
        let (issuer, _s, _a, p, _dir) = world();
        let vk = issuer.verifying_key();
        let mut vp = export_presentation_vp(&p, &|_d| Some(vk)).unwrap();
        vp.as_object_mut().unwrap().remove("verifiableCredential");
        assert!(matches!(
            import_presentation_vp(&vp),
            Err(InteropError::WrongType("verifiableCredential"))
        ));
    }

    #[test]
    fn empty_presentation_round_trips_then_verify_rejects() {
        // A zero-credential VP is structurally valid (the subject signed an empty bundle) but
        // verify_presentation rejects it ("discloses at least one claim").
        let subject = Identity::generate();
        let audience = Identity::generate().did();
        let p = build_presentation(
            &subject,
            &audience,
            "application",
            b"nonce-abcdef012345",
            Timestamp(100),
            Timestamp(10_000),
            vec![],
        );
        let vp = export_presentation_vp(&p, &|_d| None).unwrap(); // resolver never called (no claims)
        assert_eq!(vp["verifiableCredential"].as_array().unwrap().len(), 0);
        let back = import_presentation_vp(&vp).unwrap();
        assert!(back.claims.is_empty());
        let dir = IssuerDirectory::new();
        let report = verify_presentation(&back, &audience, Timestamp(200), &dir, false).unwrap();
        assert!(!report.accepted); // empty presentation is rejected
    }

    #[test]
    fn unresolved_issuer_is_an_error() {
        let (_issuer, _s, _a, p, _dir) = world();
        let resolver = |_did: &Did| None;
        assert!(matches!(
            export_presentation_vp(&p, &resolver),
            Err(InteropError::UnresolvedIssuer(_))
        ));
    }

    #[test]
    fn swapped_holder_key_is_rejected() {
        let (issuer, _s, _a, p, _dir) = world();
        let vk = issuer.verifying_key();
        let mut vp = export_presentation_vp(&p, &|_d| Some(vk)).unwrap();
        let mallory = Identity::generate();
        vp["proof"]["verificationMethod"] = json!(verification_method(&mallory.verifying_key()));
        assert!(matches!(
            import_presentation_vp(&vp),
            Err(InteropError::DidBinding { .. })
        ));
    }
}
