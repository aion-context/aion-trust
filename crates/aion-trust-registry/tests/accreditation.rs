//! Phase 3: authority, not just authenticity. A background-check provider must be
//! K-of-N accredited; an unaccredited issuer is self-asserted; revocation flips a green
//! verdict to rejected.

use aion_trust_claims::{
    build_presentation, verify_presentation, BackgroundCheckBody, Claim, ClaimBody, Validity,
};
use aion_trust_core::{Did, Identity, Timestamp};
use aion_trust_registry::{Accreditation, Registry, Status};

fn check_claim(provider: &Identity, subject: &Did) -> Claim {
    let body = ClaimBody::BackgroundCheck(BackgroundCheckBody {
        provider: "Acme Screening".into(),
        scope: vec!["criminal".into()],
        result: "clear".into(),
        performed: "2026-05-10".into(),
        valid_until: None,
        jurisdiction: "US".into(),
        fcra_compliant: true,
    });
    Claim::issue(
        provider,
        subject,
        Validity {
            from: Timestamp(0),
            until: None,
        },
        body,
    )
    .unwrap()
}

fn failed(report: &aion_trust_claims::VerificationReport, name: &str) -> bool {
    report.checks.iter().any(|c| c.name == name && !c.passed)
}

#[test]
fn accreditation_and_revocation_lifecycle() {
    let provider = Identity::generate();
    let subject = Identity::generate();
    let gov1 = Identity::generate();
    let gov2 = Identity::generate();
    let verifier = Identity::generate().did();
    let now = Timestamp(1_700_000_000);

    let claim = check_claim(&provider, &subject.did());
    let claim_id = claim.claim_id().as_str().to_string();
    let present = || {
        build_presentation(
            &subject,
            &verifier,
            "application",
            b"nonce-padding-1234",
            now,
            now.plus_seconds(3600),
            vec![claim.clone()],
        )
    };

    // Recognize the provider + accreditors; require background_check = 2-of-{gov1, gov2}.
    let mut reg = Registry::new(1);
    reg.register_issuer(provider.verifying_key());
    reg.register_accreditor(gov1.verifying_key());
    reg.register_accreditor(gov2.verifying_key());
    reg.require_accreditation("background_check", 2, vec![gov1.did(), gov2.did()]);

    // 1) Recognized but UN-accredited → self-asserted, not accepted.
    let r = verify_presentation(&present(), &verifier, now, &reg, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "issuer accredited"));

    // 2) Only 1-of-2 endorses → still insufficient.
    let mut acc1 = Accreditation::new(provider.did(), "background_check", 1, None);
    acc1.endorse(&gov1);
    reg.add_accreditation(acc1);
    assert!(
        !verify_presentation(&present(), &verifier, now, &reg, false)
            .unwrap()
            .accepted
    );

    // 3) 2-of-2 → accredited, accepted.
    let mut acc2 = Accreditation::new(provider.did(), "background_check", 1, None);
    acc2.endorse(&gov1);
    acc2.endorse(&gov2);
    reg.add_accreditation(acc2);
    let r = verify_presentation(&present(), &verifier, now, &reg, false).unwrap();
    assert!(r.accepted, "2-of-2 should accredit: {:?}", r.checks);
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "issuer accredited" && c.passed));

    // 4) Revoke the claim at epoch 2 → green flips to rejected.
    reg.revoke(&claim_id, 2);
    reg.set_epoch(2);
    let r = verify_presentation(&present(), &verifier, now, &reg, false).unwrap();
    assert!(!r.accepted);
    assert!(failed(&r, "claim not revoked"));
}

#[test]
fn forged_accreditation_signature_is_not_counted() {
    let provider = Identity::generate();
    let gov1 = Identity::generate();
    let impostor = Identity::generate(); // never registered as an accreditor
    let mut reg = Registry::new(1);
    reg.register_issuer(provider.verifying_key());
    reg.register_accreditor(gov1.verifying_key());
    reg.require_accreditation("background_check", 2, vec![gov1.did(), impostor.did()]);
    // gov1 endorses legitimately; the impostor endorses but their key isn't registered.
    let mut acc = Accreditation::new(provider.did(), "background_check", 1, None);
    acc.endorse(&gov1);
    acc.endorse(&impostor);
    reg.add_accreditation(acc);
    let standing = aion_trust_claims::TrustAnchor::standing(
        &reg,
        &provider.did(),
        "background_check",
        Timestamp(0),
    );
    assert!(
        !standing.accredited,
        "an unregistered accreditor's endorsement must not count"
    );
}

#[test]
fn one_accreditor_endorsing_twice_counts_once() {
    let provider = Identity::generate();
    let gov1 = Identity::generate();
    let gov2 = Identity::generate();
    let mut reg = Registry::new(1);
    reg.register_issuer(provider.verifying_key());
    reg.register_accreditor(gov1.verifying_key());
    reg.register_accreditor(gov2.verifying_key());
    reg.require_accreditation("background_check", 2, vec![gov1.did(), gov2.did()]);
    // gov1 endorses twice — must still count as one toward the 2-of-N threshold.
    let mut acc = Accreditation::new(provider.did(), "background_check", 1, None);
    acc.endorse(&gov1);
    acc.endorse(&gov1);
    reg.add_accreditation(acc);
    let standing = aion_trust_claims::TrustAnchor::standing(
        &reg,
        &provider.did(),
        "background_check",
        Timestamp(0),
    );
    assert!(
        !standing.accredited,
        "double-counting one accreditor must not satisfy 2-of-N"
    );
}

#[test]
fn an_accreditor_outside_the_policy_set_does_not_count() {
    let provider = Identity::generate();
    let gov1 = Identity::generate();
    let gov2 = Identity::generate();
    let outsider = Identity::generate(); // registered, but NOT in the policy's accreditor set
    let mut reg = Registry::new(1);
    reg.register_issuer(provider.verifying_key());
    reg.register_accreditor(gov1.verifying_key());
    reg.register_accreditor(gov2.verifying_key());
    reg.register_accreditor(outsider.verifying_key());
    reg.require_accreditation("background_check", 2, vec![gov1.did(), gov2.did()]);
    // gov1 (in policy) + outsider (valid sig, but not named in the policy) → only 1 counts.
    let mut acc = Accreditation::new(provider.did(), "background_check", 1, None);
    acc.endorse(&gov1);
    acc.endorse(&outsider);
    reg.add_accreditation(acc);
    let standing = aion_trust_claims::TrustAnchor::standing(
        &reg,
        &provider.did(),
        "background_check",
        Timestamp(0),
    );
    assert!(
        !standing.accredited,
        "only accreditors named in the policy count toward K-of-N"
    );
}

#[test]
fn ledger_record_carries_no_pii() {
    let mut reg = Registry::new(5);
    let rec = reg.ledger_record("blake3:opaque-id");
    assert_eq!(rec.status, Status::Issued);
    reg.revoke("blake3:opaque-id", 5);
    let rec = reg.ledger_record("blake3:opaque-id");
    assert_eq!(rec.status, Status::Revoked);
    // The serialized record has exactly {claim_id, status, epoch} — nothing personal.
    let json = serde_json::to_value(&rec).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert!(
        obj.contains_key("claim_id") && obj.contains_key("status") && obj.contains_key("epoch")
    );
}
