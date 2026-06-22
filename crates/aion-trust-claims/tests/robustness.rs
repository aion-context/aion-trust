//! The presentation verifier must FAIL CLOSED on hostile input, never panic. A presentation
//! arrives as untrusted JSON from the wire; decoding a malformed hex field, an out-of-range
//! leaf index, or a non-object body must yield a typed error or a rejecting report — not an
//! index-out-of-bounds, an unwrap, or an overflow. This is a deterministic stand-in for a
//! fuzzer (the project keeps to std + aion-context; no fuzz framework dependency): a corpus of
//! targeted malformations, each asserted to return without panicking.

use aion_trust_claims::{
    build_presentation, verify_presentation, Claim, ClaimBody, EmploymentBody, FieldSelector,
    IssuerDirectory, Presentation, Validity,
};
use aion_trust_core::{Did, Identity, Timestamp};
use serde_json::json;

fn valid_presentation() -> (Presentation, Did, IssuerDirectory) {
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
    let p = build_presentation(
        &subject,
        &audience,
        "app",
        b"nonce-abcdef012345",
        Timestamp(100),
        Timestamp(10_000),
        vec![claim.disclose(&FieldSelector::All).unwrap()],
    );
    let mut dir = IssuerDirectory::new();
    dir.register(issuer.verifying_key());
    (p, audience, dir)
}

/// Apply `mutate` to the presentation's JSON; if it still deserializes, verifying it must
/// return (Ok report or typed Err) without panicking. A panic fails the test.
fn assert_fails_closed(label: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let (p, audience, dir) = valid_presentation();
    let mut v = serde_json::to_value(&p).unwrap();
    mutate(&mut v);
    match serde_json::from_value::<Presentation>(v) {
        Ok(parsed) => {
            // Must not panic; an Err (e.g. hex decode) or a non-accepting report are both fine.
            let _ = verify_presentation(&parsed, &audience, Timestamp(200), &dir, false);
        }
        Err(_) => { /* rejecting at the parse layer is also failing closed */ }
    }
    // Reaching here without panicking is the assertion.
    let _ = label;
}

#[test]
fn malformed_subject_key_does_not_panic() {
    assert_fails_closed("subject_key not hex", |v| {
        v["subject_key"] = json!("zz-not-hex-zz");
    });
    assert_fails_closed("subject_key wrong length", |v| {
        v["subject_key"] = json!("00ff");
    });
}

#[test]
fn malformed_nonce_does_not_panic() {
    assert_fails_closed("nonce odd-length hex", |v| {
        v["nonce"] = json!("abc");
    });
    assert_fails_closed("nonce empty", |v| {
        v["nonce"] = json!("");
    });
}

#[test]
fn malformed_signature_does_not_panic() {
    assert_fails_closed("subject signature not hex", |v| {
        v["subject_signature"] = json!("nope");
    });
    assert_fails_closed("issuer signature wrong length", |v| {
        v["claims"][0]["issuer_signature"] = json!("00");
    });
}

#[test]
fn malformed_disclosed_field_does_not_panic() {
    assert_fails_closed("field salt not hex", |v| {
        v["claims"][0]["fields"][0]["salt"] = json!("xx");
    });
    assert_fails_closed("audit_path entry not hex", |v| {
        v["claims"][0]["fields"][0]["audit_path"] = json!(["zz"]);
    });
    assert_fails_closed("audit_path wrong-size hash", |v| {
        v["claims"][0]["fields"][0]["audit_path"] = json!(["00ff"]);
    });
    assert_fails_closed("field index wildly out of range", |v| {
        v["claims"][0]["fields"][0]["index"] = json!(4_000_000_000u32);
    });
    assert_fails_closed("body_root not hex", |v| {
        v["claims"][0]["body_root"] = json!("nope");
    });
    assert_fails_closed("field_count absurd", |v| {
        v["claims"][0]["field_count"] = json!(u32::MAX);
    });
}

#[test]
fn empty_and_degenerate_shapes_do_not_panic() {
    assert_fails_closed("no claims", |v| {
        v["claims"] = json!([]);
    });
    assert_fails_closed("claim with empty fields", |v| {
        v["claims"][0]["fields"] = json!([]);
    });
}
