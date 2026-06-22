//! Phase 4c: anti-replay and binding hardening. A presentation is single-use against its
//! audience, bound to that audience and its expiry window, and a stolen or truncated bundle
//! fails. Each test pins one defense (lamport's binding matrix + hoare's bar).

use aion_trust_claims::{
    build_presentation, verify_presentation, verify_presentation_with_store, Claim, ClaimBody,
    DisclosedClaim, EmploymentBody, FieldSelector, InMemoryNonceStore, IssuerDirectory,
    Presentation, Validity,
};
use aion_trust_core::{Did, Identity, Timestamp};

struct Setup {
    subject: Identity,
    audience: Did,
    dir: IssuerDirectory,
    claim: Claim,
    now: Timestamp,
}

fn setup() -> Setup {
    let issuer = Identity::generate();
    let subject = Identity::generate();
    let audience = Identity::generate().did();
    let now = Timestamp(1_700_000_000);
    let body = ClaimBody::Employment(EmploymentBody {
        employer: "Acme".into(),
        title: "Engineer".into(),
        employment_type: "full_time".into(),
        start: "2021".into(),
        end: None,
        rehire_eligible: true,
    });
    let validity = Validity {
        from: Timestamp(0),
        until: None,
    };
    let claim = Claim::issue(&issuer, &subject.did(), validity, body).unwrap();
    let mut dir = IssuerDirectory::new();
    dir.register(issuer.verifying_key());
    Setup {
        subject,
        audience,
        dir,
        claim,
        now,
    }
}

fn disclosed(claim: &Claim) -> DisclosedClaim {
    claim.disclose(&FieldSelector::All).unwrap()
}

/// Build a presentation for `audience` with an explicit `nonce` and 1-hour TTL.
fn present_with(s: &Setup, audience: &Did, nonce: &[u8]) -> Presentation {
    build_presentation(
        &s.subject,
        audience,
        "application",
        nonce,
        s.now,
        s.now.plus_seconds(3600),
        vec![disclosed(&s.claim)],
    )
}

fn failed(report: &aion_trust_claims::VerificationReport, name: &str) -> bool {
    report.checks.iter().any(|c| c.name == name && !c.passed)
}

#[test]
fn reused_nonce_to_same_audience_is_rejected() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    let p = present_with(&s, &s.audience, b"nonce-abcdef012345");
    let first =
        verify_presentation_with_store(&p, &s.audience, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(first.accepted, "first use must pass: {:?}", first.checks);
    let second =
        verify_presentation_with_store(&p, &s.audience, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(!second.accepted);
    assert!(failed(&second, "nonce fresh (not replayed)"));
}

#[test]
fn same_nonce_to_different_audiences_each_first_use_is_accepted() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    let other = Identity::generate().did();
    let nonce = b"shared-nonce-00001";
    // Two SEPARATELY signed presentations, each bound to its own audience.
    let p_a = present_with(&s, &s.audience, nonce);
    let p_b = present_with(&s, &other, nonce);
    let r_a =
        verify_presentation_with_store(&p_a, &s.audience, s.now, &s.dir, &mut store, &[]).unwrap();
    let r_b = verify_presentation_with_store(&p_b, &other, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(
        r_a.accepted && r_b.accepted,
        "store keys on (audience, nonce)"
    );
    assert_eq!(store.len(), 2);
}

#[test]
fn stolen_presentation_to_wrong_audience_fails_audience_binding() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    let other = Identity::generate().did();
    let p = present_with(&s, &s.audience, b"nonce-abcdef012345");
    // Replaying A's presentation verbatim to B: the signature is still valid (it was signed
    // over A as the audience), but the audience-binding check rejects it. The nonce is not burnt.
    let r = verify_presentation_with_store(&p, &other, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "audience matches verifier"));
    assert!(
        !failed(&r, "subject signature valid"),
        "signature is valid over the presentation's own stated audience"
    );
    assert!(
        store.is_empty(),
        "a rejected presentation must not burn a nonce"
    );
}

#[test]
fn rejected_presentation_does_not_burn_its_nonce() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    let nonce = b"nonce-abcdef012345";
    // A forged presentation (subject signature corrupted) with this nonce is rejected...
    let p = present_with(&s, &s.audience, nonce);
    let mut v = serde_json::to_value(&p).unwrap();
    v["subject_signature"] = serde_json::json!("00".repeat(64));
    let forged: Presentation = serde_json::from_value(v).unwrap();
    let bad = verify_presentation_with_store(&forged, &s.audience, s.now, &s.dir, &mut store, &[])
        .unwrap();
    assert!(!bad.accepted);
    assert!(store.is_empty());
    // ...so a legitimate presentation reusing that nonce still succeeds (no DoS poisoning).
    let good = present_with(&s, &s.audience, nonce);
    let ok =
        verify_presentation_with_store(&good, &s.audience, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(ok.accepted, "honest reuse after a failed attempt must pass");
}

#[test]
fn expired_presentation_fails_even_with_a_fresh_store() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    let p = present_with(&s, &s.audience, b"nonce-abcdef012345");
    let later = s.now.plus_seconds(3601);
    let r =
        verify_presentation_with_store(&p, &s.audience, later, &s.dir, &mut store, &[]).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "unexpired"));
}

#[test]
fn expiry_window_boundaries_are_inclusive() {
    let s = setup();
    let p = present_with(&s, &s.audience, b"nonce-abcdef012345"); // issued s.now, expires +3600
    let at = |t: Timestamp| verify_presentation(&p, &s.audience, t, &s.dir, false).unwrap();
    assert!(!at(Timestamp(s.now.0 - 1)).accepted); // before issued_at → reject
    assert!(at(s.now).accepted); // exactly issued_at → accept
    assert!(at(s.now.plus_seconds(3600)).accepted); // exactly expires_at → accept
    assert!(!at(s.now.plus_seconds(3601)).accepted); // one past expiry → reject
}

#[test]
fn degenerate_window_is_never_valid() {
    let s = setup();
    // issued_at AFTER expires_at: no instant can satisfy both bounds.
    let p = build_presentation(
        &s.subject,
        &s.audience,
        "application",
        b"nonce-abcdef012345",
        s.now.plus_seconds(100),
        s.now,
        vec![disclosed(&s.claim)],
    );
    for t in [s.now, s.now.plus_seconds(50), s.now.plus_seconds(100)] {
        let r = verify_presentation(&p, &s.audience, t, &s.dir, false).unwrap();
        assert!(!r.accepted);
        assert!(
            failed(&r, "unexpired"),
            "the window check must be the cause at t={t:?}"
        );
    }
}

#[test]
fn truncating_a_claim_breaks_the_subject_signature() {
    let s = setup();
    // A two-claim presentation; the signature binds BOTH claim ids.
    let p = build_presentation(
        &s.subject,
        &s.audience,
        "application",
        b"nonce-abcdef012345",
        s.now,
        s.now.plus_seconds(3600),
        vec![disclosed(&s.claim), disclosed(&s.claim)],
    );
    let mut v = serde_json::to_value(&p).unwrap();
    v["claims"].as_array_mut().unwrap().truncate(1); // drop a claim
    let tampered: Presentation = serde_json::from_value(v).unwrap();
    let r = verify_presentation(&tampered, &s.audience, s.now, &s.dir, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "subject signature valid"));
}

#[test]
fn all_zero_nonce_is_accepted_once_then_replay_rejected() {
    let s = setup();
    let mut store = InMemoryNonceStore::new();
    // A 16-byte all-zero nonce passes the length floor; single-use still applies.
    let p = present_with(&s, &s.audience, &[0u8; 16]);
    assert!(
        verify_presentation_with_store(&p, &s.audience, s.now, &s.dir, &mut store, &[])
            .unwrap()
            .accepted
    );
    let replay =
        verify_presentation_with_store(&p, &s.audience, s.now, &s.dir, &mut store, &[]).unwrap();
    assert!(!replay.accepted);
    assert!(failed(&replay, "nonce fresh (not replayed)"));
}
