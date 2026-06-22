//! The demo's in-memory world.
//!
//! Everything the three surfaces share lives here, behind one `Arc<Mutex<AppState>>`. There is
//! **no persistence**: state is built by [`AppState::seed`] at startup, mutated in process
//! memory, and discarded on exit. This is a *local single-operator* demo — one operator's own
//! issuer, accreditor, and candidate keys, co-located in one binary for convenience. That
//! co-location is the one thing **not** to copy into production (see `docs/WEB-SURFACES.md`):
//! a real deployment puts the wallet on the subject's device and the three surfaces on three
//! different parties' machines. The aion-context registry holds no PII in any case.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aion_trust_claims::{
    BackgroundCheckBody, Claim, ClaimBody, EducationBody, EmploymentBody, InMemoryNonceStore,
    Presentation, Validity,
};
use aion_trust_core::{Identity, Timestamp};
use aion_trust_registry::{Accreditation, Registry};
use aion_trust_wallet::Wallet;

/// One issuer the operator controls: its keypair (secret stays in memory, never rendered),
/// a human label, and the categories it may attest.
pub(crate) struct IssuerSlot {
    pub identity: Identity,
    pub label: String,
    pub categories: Vec<String>,
}

/// The whole demo world. Shared via [`Shared`]; never serialized (it holds secrets).
pub(crate) struct AppState {
    pub epoch: u64,
    pub registry: Registry,
    pub issuers: HashMap<String, IssuerSlot>,
    pub employer: Identity,
    pub wallet: Wallet,
    pub nonces: InMemoryNonceStore,
    pub last_presentation: Option<Presentation>,
    pub claim_labels: HashMap<String, String>,
}

pub(crate) type Shared = Arc<Mutex<AppState>>;

const START_EPOCH: u64 = 1;

impl AppState {
    /// Build a believable starting world: two accreditors, an employer (the audience), two
    /// accredited issuers (Acme → employment, TrustScreen → background_check), and a candidate
    /// wallet pre-loaded with one claim from each issuer.
    pub(crate) fn seed() -> Self {
        let mut registry = Registry::new(START_EPOCH);
        let accreditors = vec![Identity::generate(), Identity::generate()];
        for a in &accreditors {
            registry.register_accreditor(a.verifying_key());
        }
        let employer = Identity::generate();
        let wallet = Wallet::generate();

        let mut issuers = HashMap::new();
        let acme = accredited_issuer(&mut registry, &accreditors, "Acme Corp", "employment");
        let screen = accredited_issuer(
            &mut registry,
            &accreditors,
            "TrustScreen",
            "background_check",
        );
        let uni = accredited_issuer(&mut registry, &accreditors, "State University", "education");

        let mut claim_labels = HashMap::new();
        let mut wallet = wallet;
        seed_claim(
            &mut wallet,
            &mut claim_labels,
            &acme.identity,
            employment_example(),
            "Senior Engineer @ Acme",
        );
        seed_claim(
            &mut wallet,
            &mut claim_labels,
            &screen.identity,
            background_check_example(),
            "Background check (clear)",
        );
        seed_claim(
            &mut wallet,
            &mut claim_labels,
            &uni.identity,
            education_example(),
            "M.S. Computer Science",
        );

        issuers.insert(acme.identity.did().as_str().to_string(), acme);
        issuers.insert(screen.identity.did().as_str().to_string(), screen);
        issuers.insert(uni.identity.did().as_str().to_string(), uni);

        AppState {
            epoch: START_EPOCH,
            registry,
            issuers,
            employer,
            wallet,
            nonces: InMemoryNonceStore::new(),
            last_presentation: None,
            claim_labels,
        }
    }

    /// Re-seed in place — the demo's "reset" control. Drops all prior state.
    pub(crate) fn reset(&mut self) {
        *self = Self::seed();
    }
}

/// Register an issuer and accredit it 2-of-2 for `category` from the start epoch.
fn accredited_issuer(
    registry: &mut Registry,
    accreditors: &[Identity],
    label: &str,
    category: &str,
) -> IssuerSlot {
    let identity = Identity::generate();
    registry.register_issuer(identity.verifying_key());
    let policy: Vec<_> = accreditors.iter().map(Identity::did).collect();
    registry.require_accreditation(category, accreditors.len(), policy);
    let mut acc = Accreditation::new(identity.did(), category, START_EPOCH, None);
    for a in accreditors {
        acc.endorse(a);
    }
    registry.add_accreditation(acc);
    IssuerSlot {
        identity,
        label: label.to_string(),
        categories: vec![category.to_string()],
    }
}

/// Issue a claim to the wallet and remember its human label (best-effort; a malformed seed is
/// skipped rather than panicking — library code never unwraps).
fn seed_claim(
    wallet: &mut Wallet,
    labels: &mut HashMap<String, String>,
    issuer: &Identity,
    body: ClaimBody,
    label: &str,
) {
    let validity = Validity {
        from: Timestamp(0),
        until: None,
    };
    if let Ok(claim) = Claim::issue(issuer, &wallet.did(), validity, body) {
        labels.insert(claim.claim_id().as_str().to_string(), label.to_string());
        wallet.add(claim);
    }
}

fn employment_example() -> ClaimBody {
    ClaimBody::Employment(EmploymentBody {
        employer: "Acme Corp".into(),
        title: "Senior Engineer".into(),
        employment_type: "full_time".into(),
        start: "2021-03-01".into(),
        end: Some("2024-08-15".into()),
        rehire_eligible: true,
    })
}

fn education_example() -> ClaimBody {
    ClaimBody::Education(EducationBody {
        institution: "State University".into(),
        credential: "M.S. Computer Science".into(),
        conferred: "2020-05-20".into(),
        aion_edu_ref: None,
        degree_rank: Some(4), // master's, on the schema-pinned ordinal scale
    })
}

fn background_check_example() -> ClaimBody {
    ClaimBody::BackgroundCheck(BackgroundCheckBody {
        provider: "TrustScreen".into(),
        scope: vec!["criminal".into(), "identity".into(), "sanctions".into()],
        result: "clear".into(),
        performed: "2026-05-10".into(),
        valid_until: Some("2027-05-10".into()),
        jurisdiction: "US".into(),
        fcra_compliant: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_builds_two_accredited_issuers_and_two_claims() {
        let s = AppState::seed();
        assert_eq!(s.epoch, START_EPOCH);
        assert_eq!(s.issuers.len(), 3);
        assert_eq!(s.wallet.claims().len(), 3);
        assert!(s.last_presentation.is_none());
        // every seeded issuer is accredited 2-of-2 for its category at the start epoch
        for slot in s.issuers.values() {
            let cat = &slot.categories[0];
            let standing = aion_trust_claims::TrustAnchor::standing(
                &s.registry,
                &slot.identity.did(),
                cat,
                Timestamp::now(),
            );
            assert!(
                standing.accredited,
                "{} not accredited for {cat}",
                slot.label
            );
        }
    }

    #[test]
    fn reset_rebuilds_fresh_state() {
        let mut s = AppState::seed();
        s.epoch = 99;
        s.wallet = Wallet::generate(); // empty
        s.reset();
        assert_eq!(s.epoch, START_EPOCH);
        assert_eq!(s.wallet.claims().len(), 3);
    }
}
