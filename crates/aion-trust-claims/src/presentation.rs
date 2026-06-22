//! The [`Presentation`]: a subject-signed, audience-bound bundle of claims — the artifact
//! that replaces the résumé — and [`verify_presentation`], the offline verifier.
//!
//! Phase 1 checks presentation binding (subject key, audience, expiry, nonce, signature)
//! and, per claim, authenticity + subject-match + that the issuer is recognized + validity.
//! Issuer *accreditation* (K-of-N) and *revocation* arrive in Phase 3; here a recognized
//! issuer is one whose key the verifier holds in its [`IssuerDirectory`].

use std::collections::HashMap;

use aion_context::crypto::VerifyingKey;
use aion_trust_core::encoding::{decode_array, to_hex, SigningWriter};
use aion_trust_core::identity::verifying_key_from_hex;
use aion_trust_core::{ClaimId, Did, Identity, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::anchor::{IssuerStanding, TrustAnchor};
use crate::disclosure::{DisclosedClaim, VerifiedDisclosure};
use crate::predicate::{evaluate, PredicateRequest};

pub const PRES_DOMAIN: &[u8] = b"aion-trust/presentation/v1";

/// Minimum nonce length the verifier accepts (128-bit anti-replay).
const MIN_NONCE_LEN: usize = 16;

/// A subject-signed bundle presented to one verifier. Self-authenticating: it carries the
/// subject's public key, which must derive the stated `subject_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub presentation_id: String,
    pub subject_id: Did,
    pub subject_key: String,
    pub audience: Did,
    pub purpose: String,
    pub nonce: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub claims: Vec<DisclosedClaim>,
    pub subject_signature: String,
}

/// Build and sign a presentation for one `audience`. The seven arguments mirror the signed
/// fields 1:1; a struct would obscure that the binding is the point.
pub fn build_presentation(
    subject: &Identity,
    audience: &Did,
    purpose: &str,
    nonce: &[u8],
    issued_at: Timestamp,
    expires_at: Timestamp,
    claims: Vec<DisclosedClaim>,
) -> Presentation {
    let signing = pres_signing_bytes(
        &subject.did(),
        audience,
        purpose,
        nonce,
        issued_at,
        expires_at,
        &claims,
    );
    Presentation {
        presentation_id: to_hex(&aion_context::crypto::hash(&signing)),
        subject_id: subject.did(),
        subject_key: to_hex(&subject.verifying_key().to_bytes()),
        audience: audience.clone(),
        purpose: purpose.to_string(),
        nonce: to_hex(nonce),
        issued_at,
        expires_at,
        claims,
        subject_signature: to_hex(&subject.sign(&signing)),
    }
}

/// The verifier's trust anchor: the public keys of issuers it recognizes. (Phase 3 replaces
/// this with accreditation records resolved against aion-context.)
#[derive(Default)]
pub struct IssuerDirectory {
    keys: HashMap<Did, VerifyingKey>,
}

impl IssuerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Recognize an issuer by its public key; it is indexed under the did that key derives.
    pub fn register(&mut self, vk: VerifyingKey) {
        self.keys.insert(Did::from_key(&vk), vk);
    }

    pub fn get(&self, id: &Did) -> Option<&VerifyingKey> {
        self.keys.get(id)
    }
}

/// The simplest anchor: recognized issuers, but no accreditation and no revocation. A
/// recognized issuer's claims verify as *authentic*; nothing here makes them *authoritative*.
impl TrustAnchor for IssuerDirectory {
    fn issuer_key(&self, issuer: &Did) -> Option<VerifyingKey> {
        self.keys.get(issuer).cloned()
    }

    fn standing(&self, _issuer: &Did, _category: &str, _now: Timestamp) -> IssuerStanding {
        IssuerStanding {
            accredited: false,
            accreditation_required: false,
        }
    }

    fn is_revoked(&self, _claim_id: &ClaimId, _now: Timestamp) -> bool {
        false
    }
}

/// One verification step and whether it passed.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// The full result of verifying a presentation. `accepted` is true iff every check passed.
///
/// Through Phase 2 `accepted` means **authentic and recognized**: the subject controls the key
/// the claims were issued to, the presentation is bound to this verifier and unexpired with a
/// fresh, sufficiently-long nonce, it discloses at least one claim, and every claim is
/// issuer-signed by a key in the verifier's directory. It does **not** yet mean **accredited**
/// (issuer authorized for the category) or **unrevoked** — those arrive in Phase 3. Treat
/// `accepted` as *authentic*, not *authoritative*.
#[derive(Clone, Debug, Serialize)]
#[must_use = "the `accepted` verdict must be inspected; dropping a report ignores the result"]
pub struct VerificationReport {
    pub accepted: bool,
    pub checks: Vec<Check>,
}

fn check(checks: &mut Vec<Check>, name: &str, passed: bool, detail: impl Into<String>) {
    checks.push(Check {
        name: name.to_string(),
        passed,
        detail: detail.into(),
    });
}

/// Verify a presentation offline. `audience` is the verifier's own did; `now` the current
/// time; `nonce_already_seen` lets a caller enforce single-use nonces (see [`crate::nonce`]).
pub fn verify_presentation(
    p: &Presentation,
    audience: &Did,
    now: Timestamp,
    anchor: &impl TrustAnchor,
    nonce_already_seen: bool,
) -> Result<VerificationReport> {
    verify_presentation_with_predicates(p, audience, now, anchor, nonce_already_seen, &[])
}

/// As [`verify_presentation`], plus the verifier's `predicates`. Each predicate is satisfied
/// only by a claim that **already passed every check** (authenticity, accreditation,
/// revocation, validity) — so a predicate can only *narrow* acceptance, never grant it — and
/// the ordinal it reads is the issuer-attested, schema-pinned value, never inferred.
pub fn verify_presentation_with_predicates(
    p: &Presentation,
    audience: &Did,
    now: Timestamp,
    anchor: &impl TrustAnchor,
    nonce_already_seen: bool,
    predicates: &[PredicateRequest],
) -> Result<VerificationReport> {
    let mut checks = Vec::new();
    let subject_vk = verifying_key_from_hex(&p.subject_key)?;
    let nonce_bytes = decode_nonce(&p.nonce)?;

    let binds = Did::from_key(&subject_vk) == p.subject_id;
    check(
        &mut checks,
        "subject_id binds to key",
        binds,
        p.subject_id.to_string(),
    );
    check(
        &mut checks,
        "audience matches verifier",
        &p.audience == audience,
        p.audience.to_string(),
    );
    let unexpired = now >= p.issued_at && now <= p.expires_at;
    check(
        &mut checks,
        "unexpired",
        unexpired,
        format!("now={}, expires={}", now.0, p.expires_at.0),
    );
    check(
        &mut checks,
        "nonce fresh (not replayed)",
        !nonce_already_seen,
        p.nonce.clone(),
    );
    let nonce_ok = nonce_bytes.len() >= MIN_NONCE_LEN;
    check(
        &mut checks,
        "nonce sufficiently long",
        nonce_ok,
        format!("{} bytes", nonce_bytes.len()),
    );
    check(
        &mut checks,
        "discloses at least one claim",
        !p.claims.is_empty(),
        format!("{} claim(s)", p.claims.len()),
    );

    let signing = pres_signing_bytes(
        &p.subject_id,
        &p.audience,
        &p.purpose,
        &nonce_bytes,
        p.issued_at,
        p.expires_at,
        &p.claims,
    );
    let sig = decode_array::<64>(&p.subject_signature)?;
    let sig_ok = subject_vk.verify(&signing, &sig).is_ok();
    check(
        &mut checks,
        "subject signature valid",
        sig_ok,
        String::new(),
    );

    let mut outcomes = Vec::new();
    for claim in &p.claims {
        if let Some(outcome) = verify_one_claim(&mut checks, claim, &p.subject_id, now, anchor) {
            outcomes.push(outcome);
        }
    }
    evaluate_predicates(&mut checks, predicates, &outcomes);

    let accepted = checks.iter().all(|c| c.passed);
    Ok(VerificationReport { accepted, checks })
}

/// A claim that authenticated, with whether it passed *every* trust check (validity,
/// accreditation, revocation) — the precondition a predicate may ride on.
struct ClaimOutcome {
    category: String,
    schema_id: String,
    verified: VerifiedDisclosure,
    fully_valid: bool,
}

/// Evaluate each predicate against the claims that fully passed. A predicate holds only if some
/// fully-valid claim of the right category proves the field and satisfies the comparison;
/// a scale-version mismatch fails closed.
fn evaluate_predicates(
    checks: &mut Vec<Check>,
    predicates: &[PredicateRequest],
    outcomes: &[ClaimOutcome],
) {
    for req in predicates {
        let satisfied = outcomes.iter().any(|o| predicate_holds(req, o));
        check(checks, "predicate satisfied", satisfied, req.label());
    }
}

fn predicate_holds(req: &PredicateRequest, o: &ClaimOutcome) -> bool {
    if !o.fully_valid || o.category != req.category {
        return false;
    }
    if let Some(scale) = &req.scale_version {
        if &o.schema_id != scale {
            return false; // issuer/verifier disagree on the ordinal scale → fail closed
        }
    }
    match o.verified.value(&req.field) {
        Some(value) => evaluate(req.op, value, &req.bound).unwrap_or(false),
        None => false,
    }
}

fn verify_one_claim(
    checks: &mut Vec<Check>,
    claim: &DisclosedClaim,
    presenter: &Did,
    now: Timestamp,
    anchor: &impl TrustAnchor,
) -> Option<ClaimOutcome> {
    let id = claim.claim_id().as_str().to_string();
    let subject_ok = claim.subject_id() == presenter;
    check(checks, "claim subject matches presenter", subject_ok, id);

    let Some(issuer_vk) = anchor.issuer_key(claim.issuer_id()) else {
        check(
            checks,
            "issuer recognized",
            false,
            format!("unknown issuer {}", claim.issuer_id()),
        );
        return None;
    };
    match claim.verify(&issuer_vk) {
        Ok(verified) => {
            let trusted = authenticated_claim_checks(checks, claim, &verified, now, anchor);
            Some(ClaimOutcome {
                category: claim.category().to_string(),
                schema_id: claim.schema_id.clone(),
                verified,
                fully_valid: subject_ok && trusted,
            })
        }
        Err(reject) => {
            check(checks, "claim authentic", false, reject.to_string());
            None
        }
    }
}

/// Checks that only make sense once a disclosure's signature and every field proof are valid:
/// which fields were proven, the validity window, issuer accreditation (when the category
/// requires it), and revocation status. Returns whether all of those trust checks passed.
fn authenticated_claim_checks(
    checks: &mut Vec<Check>,
    claim: &DisclosedClaim,
    verified: &VerifiedDisclosure,
    now: Timestamp,
    anchor: &impl TrustAnchor,
) -> bool {
    let id = claim.claim_id().as_str().to_string();
    let category = verified.category();
    check(checks, "claim authentic", true, id.clone());
    for key in verified.revealed_keys() {
        check(
            checks,
            "field proven against body_root",
            true,
            key.to_string(),
        );
    }
    let within = verified.active_at(now);
    check(checks, "claim within validity", within, String::new());
    let standing = anchor.standing(claim.issuer_id(), category, now);
    let accredited_ok = if standing.accreditation_required {
        let detail = if standing.accredited {
            format!("accredited for {category}")
        } else {
            format!("NOT accredited for {category} (self-asserted)")
        };
        check(checks, "issuer accredited", standing.accredited, detail);
        standing.accredited
    } else {
        true
    };
    let not_revoked = !anchor.is_revoked(claim.claim_id(), now);
    check(checks, "claim not revoked", not_revoked, id);
    within && accredited_ok && not_revoked
}

fn decode_nonce(nonce_hex: &str) -> Result<Vec<u8>> {
    aion_trust_core::encoding::from_hex(nonce_hex)
}

// Seven args mirror the signed fields; grouping them into a struct would obscure the 1:1 binding.
fn pres_signing_bytes(
    subject: &Did,
    audience: &Did,
    purpose: &str,
    nonce: &[u8],
    issued_at: Timestamp,
    expires_at: Timestamp,
    claims: &[DisclosedClaim],
) -> Vec<u8> {
    let mut w = SigningWriter::new(PRES_DOMAIN);
    w.field(subject.as_bytes())
        .field(audience.as_bytes())
        .field(purpose.as_bytes())
        .field(nonce)
        .int(issued_at.0)
        .int(expires_at.0);
    for claim in claims {
        w.field(claim.claim_id().as_str().as_bytes());
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_core::Identity;

    #[test]
    fn pres_signing_bytes_is_nonempty_and_binds_fields() {
        let s = Did::from_string("did:aion:s".into());
        let a = Did::from_string("did:aion:a".into());
        let base = pres_signing_bytes(&s, &a, "purpose", b"nonce", Timestamp(1), Timestamp(2), &[]);
        assert!(!base.is_empty()); // kills pres_signing_bytes -> vec![]
        let b = Did::from_string("did:aion:b".into());
        assert_ne!(
            base,
            pres_signing_bytes(&s, &b, "purpose", b"nonce", Timestamp(1), Timestamp(2), &[])
        );
        assert_ne!(
            base,
            pres_signing_bytes(&s, &a, "other", b"nonce", Timestamp(1), Timestamp(2), &[])
        );
        assert_ne!(
            base,
            pres_signing_bytes(
                &s,
                &a,
                "purpose",
                b"different",
                Timestamp(1),
                Timestamp(2),
                &[]
            )
        );
        assert_ne!(
            base,
            pres_signing_bytes(&s, &a, "purpose", b"nonce", Timestamp(9), Timestamp(2), &[])
        );
        assert_ne!(
            base,
            pres_signing_bytes(&s, &a, "purpose", b"nonce", Timestamp(1), Timestamp(9), &[])
        );
    }

    #[test]
    fn issuer_directory_indexes_by_derived_did() {
        let issuer = Identity::generate();
        let mut dir = IssuerDirectory::new();
        dir.register(issuer.verifying_key());
        assert!(dir.get(&issuer.did()).is_some());
        assert!(dir
            .get(&Did::from_string("did:aion:nobody".into()))
            .is_none());
    }

    // ── Predicate verification (package-local, so the mutation gate covers this file) ──

    use crate::bodies::EducationBody;
    use crate::claim::{Claim, Validity};
    use crate::disclosure::FieldSelector;
    use crate::predicate::PredicateOp;
    use crate::ClaimBody;
    use aion_context::crypto::VerifyingKey;

    /// A controllable anchor: recognizes one issuer and lets a test dictate accreditation and
    /// revocation independently, so every `fully_valid` branch is reachable here.
    struct MockAnchor {
        vk: VerifyingKey,
        accredited: bool,
        required: bool,
        revoked: bool,
    }

    impl TrustAnchor for MockAnchor {
        fn issuer_key(&self, _issuer: &Did) -> Option<VerifyingKey> {
            Some(self.vk)
        }
        fn standing(&self, _issuer: &Did, _category: &str, _now: Timestamp) -> IssuerStanding {
            IssuerStanding {
                accredited: self.accredited,
                accreditation_required: self.required,
            }
        }
        fn is_revoked(&self, _claim_id: &ClaimId, _now: Timestamp) -> bool {
            self.revoked
        }
    }

    fn edu_claim(issuer: &Identity, subject: &Did, until: Option<Timestamp>) -> Claim {
        let body = ClaimBody::Education(EducationBody {
            institution: "State U".into(),
            credential: "M.S.".into(),
            conferred: "2020".into(),
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

    fn rank_request(op: PredicateOp, bound: i64, scale: Option<&str>) -> PredicateRequest {
        PredicateRequest {
            category: "education".into(),
            field: "degree_rank".into(),
            op,
            bound: serde_json::json!(bound),
            scale_version: scale.map(str::to_string),
        }
    }

    /// Build a presentation disclosing only `degree_rank`, signed by `signer`.
    fn rank_presentation(signer: &Identity, audience: &Did, claim: &Claim) -> Presentation {
        let d = claim
            .disclose(&FieldSelector::Only(vec!["degree_rank".into()]))
            .unwrap();
        build_presentation(
            signer,
            audience,
            "app",
            b"nonce-abcdef012345",
            Timestamp(100),
            Timestamp(10_000),
            vec![d],
        )
    }

    fn predicate_passed(report: &VerificationReport) -> bool {
        report
            .checks
            .iter()
            .find(|c| c.name == "predicate satisfied")
            .map(|c| c.passed)
            .expect("a predicate check was recorded")
    }

    fn valid_anchor(issuer: &Identity) -> MockAnchor {
        MockAnchor {
            vk: issuer.verifying_key(),
            accredited: true,
            required: false,
            revoked: false,
        }
    }

    #[test]
    fn predicate_satisfied_over_a_valid_claim_is_accepted() {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let aud = Identity::generate().did();
        let claim = edu_claim(&issuer, &subject.did(), None);
        let p = rank_presentation(&subject, &aud, &claim);
        let req = rank_request(PredicateOp::Ge, 3, Some("aion-trust/education/v1"));
        let r = verify_presentation_with_predicates(
            &p,
            &aud,
            Timestamp(200),
            &valid_anchor(&issuer),
            false,
            &[req],
        )
        .unwrap();
        assert!(r.accepted, "checks: {:?}", r.checks);
        assert!(predicate_passed(&r));
    }

    #[test]
    fn predicate_below_threshold_is_rejected() {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let aud = Identity::generate().did();
        let claim = edu_claim(&issuer, &subject.did(), None);
        let p = rank_presentation(&subject, &aud, &claim);
        let req = rank_request(PredicateOp::Ge, 5, None); // require doctorate; holder is 4
        let r = verify_presentation_with_predicates(
            &p,
            &aud,
            Timestamp(200),
            &valid_anchor(&issuer),
            false,
            &[req],
        )
        .unwrap();
        assert!(!r.accepted);
        assert!(!predicate_passed(&r));
    }

    #[test]
    fn predicate_category_mismatch_is_not_satisfied() {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let aud = Identity::generate().did();
        let claim = edu_claim(&issuer, &subject.did(), None);
        let p = rank_presentation(&subject, &aud, &claim);
        let mut req = rank_request(PredicateOp::Ge, 3, None);
        req.category = "employment".into(); // no employment claim present
        let r = verify_presentation_with_predicates(
            &p,
            &aud,
            Timestamp(200),
            &valid_anchor(&issuer),
            false,
            &[req],
        )
        .unwrap();
        assert!(!predicate_passed(&r));
    }

    #[test]
    fn predicate_scale_mismatch_fails_closed() {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let aud = Identity::generate().did();
        let claim = edu_claim(&issuer, &subject.did(), None);
        let p = rank_presentation(&subject, &aud, &claim);
        let req = rank_request(PredicateOp::Ge, 3, Some("aion-trust/education/v2")); // wrong scale
        let r = verify_presentation_with_predicates(
            &p,
            &aud,
            Timestamp(200),
            &valid_anchor(&issuer),
            false,
            &[req],
        )
        .unwrap();
        assert!(!predicate_passed(&r));
    }

    /// A satisfiable predicate must NOT hold when its claim fails a trust check. One mock per
    /// failure mode reaches every `&&` in `fully_valid`.
    #[test]
    fn predicate_never_rides_a_claim_that_failed_a_check() {
        let issuer = Identity::generate();
        let subject = Identity::generate();
        let aud = Identity::generate().did();
        let req = || rank_request(PredicateOp::Ge, 3, None);
        let check = |anchor: &MockAnchor, claim: &Claim, now: Timestamp| {
            let p = rank_presentation(&subject, &aud, claim);
            let r = verify_presentation_with_predicates(&p, &aud, now, anchor, false, &[req()])
                .unwrap();
            (r.accepted, predicate_passed(&r))
        };
        let valid = edu_claim(&issuer, &subject.did(), None);
        // revoked → predicate must not be satisfied
        let revoked_anchor = MockAnchor {
            vk: issuer.verifying_key(),
            accredited: true,
            required: false,
            revoked: true,
        };
        assert!(!check(&revoked_anchor, &valid, Timestamp(200)).1, "revoked");
        // required but unaccredited → predicate must not be satisfied
        let unaccredited = MockAnchor {
            vk: issuer.verifying_key(),
            accredited: false,
            required: true,
            revoked: false,
        };
        assert!(
            !check(&unaccredited, &valid, Timestamp(200)).1,
            "unaccredited"
        );
        // expired → predicate must not be satisfied
        let expired = edu_claim(&issuer, &subject.did(), Some(Timestamp(150)));
        assert!(
            !check(&valid_anchor(&issuer), &expired, Timestamp(200)).1,
            "expired"
        );
        // wrong subject (someone else presents the claim) → predicate must not be satisfied
        let mallory = Identity::generate();
        let p = rank_presentation(&mallory, &aud, &valid);
        let r = verify_presentation_with_predicates(
            &p,
            &aud,
            Timestamp(200),
            &valid_anchor(&issuer),
            false,
            &[req()],
        )
        .unwrap();
        assert!(!predicate_passed(&r), "wrong subject");
    }
}
