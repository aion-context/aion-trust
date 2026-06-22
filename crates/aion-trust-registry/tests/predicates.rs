//! Phase 4d: predicate proofs ride on top of the full trust pipeline. A predicate can only
//! *narrow* acceptance — it never rescues a revoked, unaccredited, or expired claim — and the
//! ordinal it reads is the issuer-attested, schema-pinned value (lamport's INV-Q3/Q4/Q5).

use aion_trust_claims::{
    build_presentation, verify_presentation, verify_presentation_with_predicates, Claim, ClaimBody,
    EducationBody, FieldSelector, PredicateOp, PredicateRequest, Presentation, Validity,
};
use aion_trust_core::{Did, Identity, Timestamp};
use aion_trust_registry::Registry;

const EDU_SCHEMA: &str = "aion-trust/education/v1";

/// An education claim carrying an issuer-attested `degree_rank` (4 = master's).
fn masters(issuer: &Identity, subject: &Did, until: Option<Timestamp>) -> Claim {
    let body = ClaimBody::Education(EducationBody {
        institution: "State University".into(),
        credential: "M.S. Computer Science".into(),
        conferred: "2020-05-20".into(),
        aion_edu_ref: None,
        degree_rank: Some(4),
    });
    Claim::issue(
        issuer,
        subject,
        Validity {
            from: Timestamp(0),
            until,
        },
        body,
    )
    .unwrap()
}

struct World {
    subject: Identity,
    audience: Did,
    reg: Registry,
    issuer: Identity,
    now: Timestamp,
}

fn world() -> World {
    let issuer = Identity::generate();
    let subject = Identity::generate();
    let audience = Identity::generate().did();
    let mut reg = Registry::new(1);
    reg.register_issuer(issuer.verifying_key());
    World {
        subject,
        audience,
        reg,
        issuer,
        now: Timestamp(1_700_000_000),
    }
}

/// Disclose ONLY `degree_rank` — the minimal field that answers "degree ≥ bachelor's".
fn present_rank_only(w: &World, claim: &Claim) -> Presentation {
    let d = claim
        .disclose(&FieldSelector::Only(vec!["degree_rank".into()]))
        .unwrap();
    build_presentation(
        &w.subject,
        &w.audience,
        "application",
        b"nonce-abcdef012345",
        w.now,
        w.now.plus_seconds(3600),
        vec![d],
    )
}

fn ge_bachelor() -> PredicateRequest {
    PredicateRequest {
        category: "education".into(),
        field: "degree_rank".into(),
        op: PredicateOp::Ge,
        bound: serde_json::json!(3),
        scale_version: Some(EDU_SCHEMA.into()),
    }
}

fn verify(w: &World, p: &Presentation, preds: &[PredicateRequest]) -> bool {
    verify_presentation_with_predicates(p, &w.audience, w.now, &w.reg, false, preds)
        .unwrap()
        .accepted
}

#[test]
fn predicate_satisfied_by_minimal_disclosure() {
    let w = world();
    let claim = masters(&w.issuer, &w.subject.did(), None);
    let p = present_rank_only(&w, &claim);
    // Only degree_rank is on the wire — not the credential or institution.
    let disclosed: Vec<&str> = p.claims[0].disclosed_keys().collect();
    assert_eq!(disclosed, ["degree_rank"]);
    assert!(
        verify(&w, &p, &[ge_bachelor()]),
        "master's ≥ bachelor's holds"
    );
}

#[test]
fn predicate_below_threshold_is_rejected() {
    let w = world();
    let claim = masters(&w.issuer, &w.subject.did(), None);
    let p = present_rank_only(&w, &claim);
    let too_high = PredicateRequest {
        bound: serde_json::json!(5), // require doctorate; holder has master's (4)
        ..ge_bachelor()
    };
    assert!(!verify(&w, &p, &[too_high]));
}

#[test]
fn predicate_over_revoked_claim_is_rejected() {
    // Bypass-1: a satisfied predicate must NOT rescue a revoked claim.
    let mut w = world();
    let claim = masters(&w.issuer, &w.subject.did(), None);
    let p = present_rank_only(&w, &claim);
    assert!(verify(&w, &p, &[ge_bachelor()]), "valid before revocation");
    w.reg.revoke(claim.claim_id().as_str(), 2);
    w.reg.set_epoch(2);
    assert!(
        !verify(&w, &p, &[ge_bachelor()]),
        "revoked → rejected despite predicate"
    );
}

#[test]
fn predicate_over_expired_claim_is_rejected() {
    // Bypass-3: a satisfied predicate must NOT rescue an out-of-validity claim.
    let w = world();
    let claim = masters(&w.issuer, &w.subject.did(), Some(Timestamp(w.now.0 - 1)));
    let p = present_rank_only(&w, &claim);
    assert!(!verify(&w, &p, &[ge_bachelor()]));
}

#[test]
fn predicate_over_unaccredited_required_category_is_rejected() {
    // Bypass-2: a predicate over a category that REQUIRES accreditation, from an unaccredited
    // issuer, is self-asserted and must fail — the predicate cannot launder it.
    let mut w = world();
    let gov1 = Identity::generate();
    let gov2 = Identity::generate();
    w.reg.register_accreditor(gov1.verifying_key());
    w.reg.register_accreditor(gov2.verifying_key());
    w.reg
        .require_accreditation("education", 2, vec![gov1.did(), gov2.did()]);
    let claim = masters(&w.issuer, &w.subject.did(), None); // issuer NOT accredited
    let p = present_rank_only(&w, &claim);
    assert!(!verify(&w, &p, &[ge_bachelor()]));
}

#[test]
fn scale_version_mismatch_fails_closed() {
    // INV-Q4: if the verifier's scale doesn't match the issuer's signed schema, refuse.
    let w = world();
    let claim = masters(&w.issuer, &w.subject.did(), None);
    let p = present_rank_only(&w, &claim);
    let wrong_scale = PredicateRequest {
        scale_version: Some("aion-trust/education/v2".into()),
        ..ge_bachelor()
    };
    assert!(!verify(&w, &p, &[wrong_scale]));
}

#[test]
fn predicate_accept_implies_full_disclosure_accept() {
    // INV-Q3 (master): anything a predicate accepts, a full disclosure + the four checks also
    // accepts. Conversely a revoked claim is rejected on both paths.
    let mut w = world();
    let claim = masters(&w.issuer, &w.subject.did(), None);
    let pred_p = present_rank_only(&w, &claim);
    assert!(verify(&w, &pred_p, &[ge_bachelor()]));
    // full disclosure of the same claim also accepts
    let full = claim.disclose(&FieldSelector::All).unwrap();
    let full_p = build_presentation(
        &w.subject,
        &w.audience,
        "application",
        b"nonce-abcdef012345",
        w.now,
        w.now.plus_seconds(3600),
        vec![full],
    );
    assert!(
        verify_presentation(&full_p, &w.audience, w.now, &w.reg, false)
            .unwrap()
            .accepted
    );
    // revoke → both paths reject
    w.reg.revoke(claim.claim_id().as_str(), 2);
    w.reg.set_epoch(2);
    assert!(!verify(&w, &pred_p, &[ge_bachelor()]));
}
