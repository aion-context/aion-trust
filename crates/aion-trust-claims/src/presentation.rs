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
use aion_trust_core::{Did, Identity, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::claim::Claim;

pub const PRES_DOMAIN: &[u8] = b"aion-trust/presentation/v1";

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
    pub claims: Vec<Claim>,
    pub subject_signature: String,
}

/// Build and sign a presentation for one `audience`. The required arguments make it
/// impossible to forget the audience/nonce/expiry binding.
#[allow(clippy::too_many_arguments)] // a builder lands in Phase 2; the binding is the point
pub fn build_presentation(
    subject: &Identity,
    audience: &Did,
    purpose: &str,
    nonce: &[u8],
    issued_at: Timestamp,
    expires_at: Timestamp,
    claims: Vec<Claim>,
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

/// One verification step and whether it passed.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// The full result of verifying a presentation. `accepted` iff every check passed.
#[derive(Clone, Debug, Serialize)]
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
/// time; `nonce_already_seen` lets a caller enforce single-use nonces (Phase 4 stores them).
pub fn verify_presentation(
    p: &Presentation,
    audience: &Did,
    now: Timestamp,
    directory: &IssuerDirectory,
    nonce_already_seen: bool,
) -> Result<VerificationReport> {
    let mut checks = Vec::new();
    let subject_vk = verifying_key_from_hex(&p.subject_key)?;

    let binds = Did::from_key(&subject_vk) == p.subject_id;
    check(&mut checks, "subject_id binds to key", binds, p.subject_id.to_string());
    check(&mut checks, "audience matches verifier", &p.audience == audience, p.audience.to_string());
    let unexpired = now >= p.issued_at && now <= p.expires_at;
    check(&mut checks, "unexpired", unexpired, format!("now={}, expires={}", now.0, p.expires_at.0));
    check(&mut checks, "nonce fresh (not replayed)", !nonce_already_seen, p.nonce.clone());

    let signing = pres_signing_bytes(
        &p.subject_id, &p.audience, &p.purpose, &decode_nonce(&p.nonce)?,
        p.issued_at, p.expires_at, &p.claims,
    );
    let sig = decode_array::<64>(&p.subject_signature)?;
    let sig_ok = subject_vk.verify(&signing, &sig).is_ok();
    check(&mut checks, "subject signature valid", sig_ok, String::new());

    for claim in &p.claims {
        verify_one_claim(&mut checks, claim, &p.subject_id, now, directory);
    }

    let accepted = checks.iter().all(|c| c.passed);
    Ok(VerificationReport { accepted, checks })
}

fn verify_one_claim(
    checks: &mut Vec<Check>,
    claim: &Claim,
    presenter: &Did,
    now: Timestamp,
    directory: &IssuerDirectory,
) {
    let id = claim.claim_id().as_str().to_string();
    check(checks, "claim subject matches presenter", &claim.subject_id == presenter, id.clone());

    let Some(issuer_vk) = directory.get(claim.issuer_id()) else {
        check(checks, "issuer recognized", false, format!("unknown issuer {}", claim.issuer_id()));
        return;
    };
    match claim.verify(issuer_vk) {
        Ok(verified) => {
            check(checks, "claim authentic", true, id);
            check(checks, "claim within validity", verified.active_at(now), String::new());
        }
        Err(reject) => check(checks, "claim authentic", false, reject.to_string()),
    }
}

fn decode_nonce(nonce_hex: &str) -> Result<Vec<u8>> {
    aion_trust_core::encoding::from_hex(nonce_hex)
}

#[allow(clippy::too_many_arguments)] // mirrors the signed fields; grouping would obscure them
fn pres_signing_bytes(
    subject: &Did,
    audience: &Did,
    purpose: &str,
    nonce: &[u8],
    issued_at: Timestamp,
    expires_at: Timestamp,
    claims: &[Claim],
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
        assert_ne!(base, pres_signing_bytes(&s, &b, "purpose", b"nonce", Timestamp(1), Timestamp(2), &[]));
        assert_ne!(base, pres_signing_bytes(&s, &a, "other", b"nonce", Timestamp(1), Timestamp(2), &[]));
        assert_ne!(base, pres_signing_bytes(&s, &a, "purpose", b"different", Timestamp(1), Timestamp(2), &[]));
        assert_ne!(base, pres_signing_bytes(&s, &a, "purpose", b"nonce", Timestamp(9), Timestamp(2), &[]));
        assert_ne!(base, pres_signing_bytes(&s, &a, "purpose", b"nonce", Timestamp(1), Timestamp(9), &[]));
    }

    #[test]
    fn issuer_directory_indexes_by_derived_did() {
        let issuer = Identity::generate();
        let mut dir = IssuerDirectory::new();
        dir.register(issuer.verifying_key());
        assert!(dir.get(&issuer.did()).is_some());
        assert!(dir.get(&Did::from_string("did:aion:nobody".into())).is_none());
    }
}
