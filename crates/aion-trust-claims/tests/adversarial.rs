//! The adversarial set: every failure mode the verifier must reject (hoare's bar).
//! A presentation is accepted only when *every* check passes; each test proves one
//! specific defense fires.

use aion_trust_claims::*;
use aion_trust_core::{Did, Identity, Timestamp};
use serde_json::json;

fn emp_body() -> ClaimBody {
    ClaimBody::Employment(EmploymentBody {
        employer: "Acme Corp".into(),
        title: "Senior Engineer".into(),
        employment_type: "full_time".into(),
        start: "2021-03-01".into(),
        end: Some("2024-08-15".into()),
        rehire_eligible: true,
    })
}

struct Setup {
    subject: Identity,
    verifier: Did,
    dir: IssuerDirectory,
    claim: Claim,
    now: Timestamp,
}

fn setup() -> Setup {
    let issuer = Identity::generate();
    let subject = Identity::generate();
    let verifier = Identity::generate().did();
    let now = Timestamp(1_700_000_000);
    let validity = Validity {
        from: Timestamp(1_600_000_000),
        until: None,
    };
    let claim = Claim::issue(&issuer, &subject.did(), validity, emp_body()).expect("issue");
    let mut dir = IssuerDirectory::new();
    dir.register(issuer.verifying_key());
    Setup {
        subject,
        verifier,
        dir,
        claim,
        now,
    }
}

fn present(s: &Setup, signer: &Identity, claims: Vec<Claim>) -> Presentation {
    build_presentation(
        signer,
        &s.verifier,
        "application:senior-engineer",
        b"nonce-abcdef012345",
        s.now,
        s.now.plus_seconds(3600),
        claims,
    )
}

fn failed(report: &VerificationReport, name: &str) -> bool {
    report.checks.iter().any(|c| c.name == name && !c.passed)
}

#[test]
fn happy_path_is_accepted() {
    let s = setup();
    let p = present(&s, &s.subject, vec![s.claim.clone()]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(r.accepted, "checks: {:?}", r.checks);
}

#[test]
fn json_round_trip_still_verifies() {
    let s = setup();
    let p = present(&s, &s.subject, vec![s.claim.clone()]);
    let wire = serde_json::to_string(&p).unwrap();
    let parsed: Presentation = serde_json::from_str(&wire).unwrap();
    let r = verify_presentation(&parsed, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(r.accepted, "checks: {:?}", r.checks);
}

#[test]
fn tampered_body_is_rejected() {
    let s = setup();
    let mut v = serde_json::to_value(&s.claim).unwrap();
    v["body"]["title"] = json!("Chief Executive Officer");
    let tampered: Claim = serde_json::from_value(v).unwrap();
    let p = present(&s, &s.subject, vec![tampered]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "claim authentic"));
}

#[test]
fn forged_claim_signature_is_rejected() {
    let s = setup();
    let mut v = serde_json::to_value(&s.claim).unwrap();
    let bad: String = v["issuer_signature"]
        .as_str()
        .unwrap()
        .chars()
        .rev()
        .collect();
    v["issuer_signature"] = json!(bad);
    let forged: Claim = serde_json::from_value(v).unwrap();
    let p = present(&s, &s.subject, vec![forged]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "claim authentic"));
}

#[test]
fn presenting_another_subjects_claim_is_rejected() {
    let s = setup();
    let mallory = Identity::generate();
    let p = present(&s, &mallory, vec![s.claim.clone()]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "claim subject matches presenter"));
}

#[test]
fn unknown_issuer_is_not_accepted() {
    let s = setup();
    let empty = IssuerDirectory::new();
    let p = present(&s, &s.subject, vec![s.claim.clone()]);
    let r = verify_presentation(&p, &s.verifier, s.now, &empty, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "issuer recognized"));
}

#[test]
fn wrong_audience_is_rejected() {
    let s = setup();
    let p = present(&s, &s.subject, vec![s.claim.clone()]);
    let other = Identity::generate().did();
    let r = verify_presentation(&p, &other, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "audience matches verifier"));
}

#[test]
fn expired_presentation_is_rejected() {
    let s = setup();
    let p = build_presentation(
        &s.subject,
        &s.verifier,
        "application",
        b"nonce-padding-0001",
        s.now,
        s.now.plus_seconds(10),
        vec![s.claim.clone()],
    );
    let r = verify_presentation(&p, &s.verifier, s.now.plus_seconds(100), &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "unexpired"));
}

#[test]
fn replayed_nonce_is_rejected() {
    let s = setup();
    let p = present(&s, &s.subject, vec![s.claim.clone()]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, true).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "nonce fresh (not replayed)"));
}

#[test]
fn claim_outside_its_validity_window_is_rejected() {
    let issuer = Identity::generate();
    let subject = Identity::generate();
    let verifier = Identity::generate().did();
    let validity = Validity {
        from: Timestamp(1_000),
        until: Some(Timestamp(2_000)),
    };
    let claim = Claim::issue(&issuer, &subject.did(), validity, emp_body()).unwrap();
    let mut dir = IssuerDirectory::new();
    dir.register(issuer.verifying_key());
    let now = Timestamp(5_000);
    let p = build_presentation(
        &subject,
        &verifier,
        "application",
        b"nonce-padding-0002",
        now,
        now.plus_seconds(60),
        vec![claim],
    );
    let r = verify_presentation(&p, &verifier, now, &dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "claim within validity"));
}

#[test]
fn empty_presentation_is_rejected() {
    let s = setup();
    let p = present(&s, &s.subject, vec![]);
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "discloses at least one claim"));
}

#[test]
fn short_nonce_is_rejected() {
    let s = setup();
    let p = build_presentation(
        &s.subject,
        &s.verifier,
        "application",
        b"short",
        s.now,
        s.now.plus_seconds(3600),
        vec![s.claim.clone()],
    );
    let r = verify_presentation(&p, &s.verifier, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "nonce sufficiently long"));
}

#[test]
fn same_body_yields_distinct_claims_via_salt() {
    let issuer = Identity::generate();
    let subject = Identity::generate().did();
    let v = Validity {
        from: Timestamp(0),
        until: None,
    };
    let c1 = Claim::issue(&issuer, &subject, v.clone(), emp_body()).unwrap();
    let c2 = Claim::issue(&issuer, &subject, v, emp_body()).unwrap();
    // Hiding commitment: identical bodies, different salts ⇒ different claim_ids.
    assert_ne!(c1.claim_id(), c2.claim_id());
}
