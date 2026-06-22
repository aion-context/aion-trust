//! The Phase 2 headline: a background check run **once** becomes a reusable claim the
//! candidate carries — presented to many employers instead of re-purchased each time.

use aion_trust_claims::{
    verify_presentation, BackgroundCheckBody, Claim, ClaimBody, IssuerDirectory, Validity,
};
use aion_trust_core::{Identity, Timestamp};
use aion_trust_wallet::Wallet;

#[test]
fn one_background_check_is_reused_across_two_employers() {
    // The accredited screening provider runs the check ONCE and issues it to the subject.
    let provider = Identity::generate();
    let mut wallet = Wallet::generate();
    let subject = wallet.did();
    let body = ClaimBody::BackgroundCheck(BackgroundCheckBody {
        provider: "Acme Screening".into(),
        scope: vec!["criminal".into(), "identity".into(), "sanctions".into()],
        result: "clear".into(),
        performed: "2026-05-10".into(),
        valid_until: Some("2027-05-10".into()),
        jurisdiction: "US".into(),
        fcra_compliant: true,
    });
    let check = Claim::issue(
        &provider,
        &subject,
        Validity {
            from: Timestamp(0),
            until: None,
        },
        body,
    )
    .unwrap();
    let check_id = check.claim_id().as_str().to_string();
    wallet.add(check);

    // Both employers recognize the screening provider.
    let mut directory = IssuerDirectory::new();
    directory.register(provider.verifying_key());
    let now = Timestamp(1_700_000_000);

    // Employer A accepts it.
    let employer_a = Identity::generate().did();
    let pres_a = wallet
        .present_all(
            &employer_a,
            "application:role-a",
            std::slice::from_ref(&check_id),
            3600,
            now,
        )
        .unwrap();
    let report_a = verify_presentation(&pres_a, &employer_a, now, &directory, false).unwrap();
    assert!(report_a.accepted, "employer A: {:?}", report_a.checks);

    // Employer B accepts the SAME check — no new screening purchased.
    let employer_b = Identity::generate().did();
    let pres_b = wallet
        .present_all(
            &employer_b,
            "application:role-b",
            std::slice::from_ref(&check_id),
            3600,
            now,
        )
        .unwrap();
    let report_b = verify_presentation(&pres_b, &employer_b, now, &directory, false).unwrap();
    assert!(report_b.accepted, "employer B: {:?}", report_b.checks);

    // And the presentation built for A must NOT verify at B — audience binding holds.
    let cross = verify_presentation(&pres_a, &employer_b, now, &directory, false).unwrap();
    assert!(
        !cross.accepted,
        "A's presentation must not be replayable at B"
    );
}
