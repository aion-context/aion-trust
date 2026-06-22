//! aion-trust-registry — the federation layer: issuer **accreditation** (K-of-N), epoch-scoped
//! **revocation**, and the non-PII [`LedgerRecord`].
//!
//! This is what turns a green verdict from *authentic* into *authoritative*. A [`Registry`]
//! implements [`TrustAnchor`], so the existing verifier consults it with no change: a claim
//! from a recognized-but-unaccredited issuer is *self-asserted*; one from a K-of-N-accredited,
//! unrevoked issuer is *accredited*.
//!
//! **No PII here.** The registry holds only keys, accreditation records, schemas, and opaque
//! claim *status*. Personal data never reaches it — that is the load-bearing invariant.

use std::collections::{HashMap, HashSet};

use aion_context::crypto::VerifyingKey;
use aion_trust_claims::{IssuerStanding, TrustAnchor};
use aion_trust_core::encoding::{decode_array, to_hex, SigningWriter};
use aion_trust_core::{ClaimId, Did, Identity, Timestamp};
use serde::{Deserialize, Serialize};

pub const ACCRED_DOMAIN: &[u8] = b"aion-trust/accreditation/v1";

/// The status of a claim on the ledger. Carries no PII.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Issued,
    Revoked,
}

/// The only ledger-facing record type: opaque claim id, status, epoch — never any PII.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub claim_id: String,
    pub status: Status,
    pub epoch: u64,
}

/// One accreditor's endorsement of an accreditation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccreditorSig {
    pub accreditor: Did,
    pub signature: String,
}

/// A signed record that an issuer may attest a category, valid from an epoch. Trusted only
/// when ≥ K distinct policy accreditors have endorsed it (verified against the registry).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accreditation {
    pub issuer_id: Did,
    pub category: String,
    pub from_epoch: u64,
    pub until_epoch: Option<u64>,
    pub signatures: Vec<AccreditorSig>,
}

impl Accreditation {
    pub fn new(
        issuer_id: Did,
        category: impl Into<String>,
        from_epoch: u64,
        until_epoch: Option<u64>,
    ) -> Self {
        Self {
            issuer_id,
            category: category.into(),
            from_epoch,
            until_epoch,
            signatures: Vec::new(),
        }
    }

    /// Add an accreditor's endorsement (a signature over the record's content).
    pub fn endorse(&mut self, accreditor: &Identity) {
        let bytes = self.signing_bytes();
        self.signatures.push(AccreditorSig {
            accreditor: accreditor.did(),
            signature: to_hex(&accreditor.sign(&bytes)),
        });
    }

    fn active_at(&self, epoch: u64) -> bool {
        self.from_epoch <= epoch && self.until_epoch.is_none_or(|u| epoch <= u)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut w = SigningWriter::new(ACCRED_DOMAIN);
        w.field(self.issuer_id.as_bytes())
            .field(self.category.as_bytes())
            .int(self.from_epoch as i64);
        match self.until_epoch {
            Some(e) => {
                w.field(b"until").int(e as i64);
            }
            None => {
                w.field(b"open");
            }
        }
        w.into_bytes()
    }
}

/// A category's accreditation rule: require `k` of the listed accreditors.
struct PolicyRule {
    k: usize,
    accreditors: Vec<Did>,
}

/// The verifier's federation state: recognized issuers, accreditor keys, accreditation records,
/// per-category K-of-N policy, revocations, and the current epoch.
#[derive(Default)]
pub struct Registry {
    issuer_keys: HashMap<Did, VerifyingKey>,
    accreditor_keys: HashMap<Did, VerifyingKey>,
    accreditations: Vec<Accreditation>,
    policy: HashMap<String, PolicyRule>,
    revoked: HashMap<String, u64>,
    epoch: u64,
}

impl Registry {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            ..Self::default()
        }
    }

    pub fn register_issuer(&mut self, key: VerifyingKey) {
        self.issuer_keys.insert(Did::from_key(&key), key);
    }

    pub fn register_accreditor(&mut self, key: VerifyingKey) {
        self.accreditor_keys.insert(Did::from_key(&key), key);
    }

    /// Require `k` of `accreditors` to accredit any issuer for `category` (high-assurance).
    pub fn require_accreditation(
        &mut self,
        category: impl Into<String>,
        k: usize,
        accreditors: Vec<Did>,
    ) {
        self.policy
            .insert(category.into(), PolicyRule { k, accreditors });
    }

    pub fn add_accreditation(&mut self, accreditation: Accreditation) {
        self.accreditations.push(accreditation);
    }

    /// Mark a claim revoked as of `epoch`.
    pub fn revoke(&mut self, claim_id: &str, epoch: u64) {
        self.revoked.insert(claim_id.to_string(), epoch);
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// The non-PII ledger record for a claim at the current epoch.
    pub fn ledger_record(&self, claim_id: &str) -> LedgerRecord {
        let revoked = self.revoked.get(claim_id).is_some_and(|&e| e <= self.epoch);
        LedgerRecord {
            claim_id: claim_id.to_string(),
            status: if revoked {
                Status::Revoked
            } else {
                Status::Issued
            },
            epoch: self.epoch,
        }
    }

    fn is_accredited(&self, issuer: &Did, category: &str) -> bool {
        let Some(rule) = self.policy.get(category) else {
            return false; // not a required category — accreditation is moot
        };
        self.accreditations.iter().any(|a| {
            &a.issuer_id == issuer
                && a.category == category
                && a.active_at(self.epoch)
                && self.valid_endorsements(a, rule) >= rule.k
        })
    }

    fn valid_endorsements(&self, accreditation: &Accreditation, rule: &PolicyRule) -> usize {
        let bytes = accreditation.signing_bytes();
        let mut distinct = HashSet::new();
        for sig in &accreditation.signatures {
            if distinct.contains(sig.accreditor.as_str())
                || !rule.accreditors.contains(&sig.accreditor)
            {
                continue;
            }
            let Some(vk) = self.accreditor_keys.get(&sig.accreditor) else {
                continue;
            };
            let Ok(sig_bytes) = decode_array::<64>(&sig.signature) else {
                continue;
            };
            if vk.verify(&bytes, &sig_bytes).is_ok() {
                distinct.insert(sig.accreditor.as_str());
            }
        }
        distinct.len()
    }
}

impl TrustAnchor for Registry {
    fn issuer_key(&self, issuer: &Did) -> Option<VerifyingKey> {
        self.issuer_keys.get(issuer).cloned()
    }

    fn standing(&self, issuer: &Did, category: &str, _now: Timestamp) -> IssuerStanding {
        let accreditation_required = self.policy.contains_key(category);
        IssuerStanding {
            accredited: accreditation_required && self.is_accredited(issuer, category),
            accreditation_required,
        }
    }

    fn is_revoked(&self, claim_id: &ClaimId, _now: Timestamp) -> bool {
        self.revoked
            .get(claim_id.as_str())
            .is_some_and(|&e| e <= self.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(category: &str, from: u64, until: Option<u64>) -> Accreditation {
        Accreditation::new(
            Did::from_string("did:aion:issuer".into()),
            category,
            from,
            until,
        )
    }

    #[test]
    fn accreditation_signing_bytes_binds_every_field() {
        let base = acc("background_check", 1, None).signing_bytes();
        assert!(!base.is_empty());
        assert_ne!(base, acc("identity", 1, None).signing_bytes()); // category
        assert_ne!(base, acc("background_check", 2, None).signing_bytes()); // from_epoch
        assert_ne!(base, acc("background_check", 1, Some(9)).signing_bytes()); // open vs until arm
        let other = Accreditation::new(
            Did::from_string("did:aion:other".into()),
            "background_check",
            1,
            None,
        );
        assert_ne!(base, other.signing_bytes()); // issuer
    }

    #[test]
    fn active_at_window_is_inclusive() {
        let a = acc("c", 2, Some(4));
        assert!(!a.active_at(1));
        assert!(a.active_at(2));
        assert!(a.active_at(4));
        assert!(!a.active_at(5));
        assert!(acc("c", 2, None).active_at(1_000)); // open-ended
    }
}
