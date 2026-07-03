//! Issuer-committed reliance — the commitment a claim carries to the claims it was issued *in
//! reliance on*. The `reliance_root` + `reliance_count` are Merkleized exactly like the body
//! ([`crate::fields`]) and folded into the issuer signature, so the dependency structure is
//! authenticated by the issuer and disclosed by the subject — never written to the shared
//! ledger. This module is the single source of truth for building that commitment; see
//! `docs/DEPENDENCY-TRUST.md`.

use aion_context::crypto::{self, keyed_hash};
use aion_trust_core::encoding::SigningWriter;
use aion_trust_core::merkle::{merkle_root, reliance_leaf_hash, RELIANCE_LEAF_DOMAIN};
use aion_trust_core::ClaimId;
use serde::{Deserialize, Serialize};

use crate::claim::ClaimReject;

/// Domain for deriving a reliance leaf's `kind` sub-commitment salt from the master salt.
const RELIANCE_KIND_SALT_DOMAIN: &[u8] = b"aion-trust/reliance-kind-salt/v1";
/// Domain for the `kind` sub-commitment itself.
const RELIANCE_KIND_COMMIT_DOMAIN: &[u8] = b"aion-trust/reliance-kind-commit/v1";

/// Why claim B was issued in reliance on claim A. Committed (hidden) in the reliance leaf via a
/// salted sub-commitment: a bare revocation check never needs it, so the subject discloses it
/// only to tell the provenance story.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliesKind {
    IdentityBasis,
    PriorCheck,
    Assessor,
    Referee,
    Renews,
    Endorses,
}

impl ReliesKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReliesKind::IdentityBasis => "identity_basis",
            ReliesKind::PriorCheck => "prior_check",
            ReliesKind::Assessor => "assessor",
            ReliesKind::Referee => "referee",
            ReliesKind::Renews => "renews",
            ReliesKind::Endorses => "endorses",
        }
    }
}

/// A dependency an issuer declares for the claim it is issuing: "issued in reliance on
/// `from_claim_id`", with `kind` recording why. The issuer's input to the reliance commitment;
/// kept privately with the claim (wallet-only), like the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliesOn {
    pub from_claim_id: ClaimId,
    pub kind: ReliesKind,
}

/// Per-index reliance leaf salt: `keyed_hash(master_salt, RELIANCE_LEAF_DOMAIN || index)`.
/// Deterministic from the master salt, independent across leaves, and one-way — so a disclosed
/// leaf reveals nothing about the withheld ones (mirrors [`crate::fields`]).
fn derive_reliance_salt(master_salt: &[u8; 32], index: u32) -> [u8; 32] {
    let mut w = SigningWriter::new(RELIANCE_LEAF_DOMAIN);
    w.u32(index);
    keyed_hash(master_salt, &w.into_bytes())
}

/// Per-index salt for the `kind` sub-commitment, under its own domain so it can never equal the
/// leaf salt at the same index.
fn derive_kind_salt(master_salt: &[u8; 32], index: u32) -> [u8; 32] {
    let mut w = SigningWriter::new(RELIANCE_KIND_SALT_DOMAIN);
    w.u32(index);
    keyed_hash(master_salt, &w.into_bytes())
}

/// A hiding commitment to a reliance `kind`: `hash(domain || kind_salt || kind)`. The salt is
/// high-entropy (master-salt-derived), so committing to the leaf's `from_claim_id` does not
/// commit the verifier to learning the `kind`.
fn kind_commit(kind: ReliesKind, kind_salt: &[u8; 32]) -> [u8; 32] {
    let mut w = SigningWriter::new(RELIANCE_KIND_COMMIT_DOMAIN);
    w.field(kind_salt).field(kind.as_str().as_bytes());
    crypto::hash(&w.into_bytes())
}

/// The signed root for a claim that declares NO reliance. A fixed sentinel — *not* a Merkle root
/// (undefined for zero leaves) — so `reliance_count = 0` is a **signed** statement and an absent
/// commitment can never be forged into "no reliance".
pub fn empty_reliance_root() -> [u8; 32] {
    crypto::hash(b"aion-trust/reliance-empty/v1")
}

/// A reliance leaf decomposed for commitment and disclosure — the single source of truth, so
/// issuing and disclosure always hash the same bytes (mirrors [`crate::fields::BodyLeaf`]). The
/// `kind` is present only as its hiding sub-commitment, so disclosing a leaf need not reveal it.
pub(crate) struct ReliesLeaf {
    pub index: u32,
    pub from_claim_id: ClaimId,
    pub salt: [u8; 32],
    pub kind_commit: [u8; 32],
    pub hash: [u8; 32],
}

/// Decompose declared reliance into ordered, per-index, domain-tagged leaves under `master_salt`.
/// Used by both [`reliance_commitment`] (which Merkleizes the hashes) and disclosure (which needs
/// the salts, `kind` sub-commitments, and audit paths).
pub(crate) fn reliance_leaves(
    master_salt: &[u8; 32],
    targets: &[ReliesOn],
) -> Result<Vec<ReliesLeaf>, ClaimReject> {
    let mut leaves = Vec::with_capacity(targets.len());
    for (i, target) in targets.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| ClaimReject::Malformed)?;
        let salt = derive_reliance_salt(master_salt, index);
        let kind_salt = derive_kind_salt(master_salt, index);
        let kind_commit = kind_commit(target.kind, &kind_salt);
        let hash = reliance_leaf_hash(
            index,
            &salt,
            target.from_claim_id.as_str().as_bytes(),
            &kind_commit,
        );
        leaves.push(ReliesLeaf {
            index,
            from_claim_id: target.from_claim_id.clone(),
            salt,
            kind_commit,
            hash,
        });
    }
    Ok(leaves)
}

/// Commit declared reliance as a Merkle root over its leaves, returning the root and the leaf
/// count. Zero targets yield the [`empty_reliance_root`] sentinel and count 0. Both are meant to
/// be folded into the issuer signature.
pub fn reliance_commitment(
    master_salt: &[u8; 32],
    targets: &[ReliesOn],
) -> Result<([u8; 32], u32), ClaimReject> {
    let leaves = reliance_leaves(master_salt, targets)?;
    let count = u32::try_from(leaves.len()).map_err(|_| ClaimReject::Malformed)?;
    if leaves.is_empty() {
        return Ok((empty_reliance_root(), 0));
    }
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
    let root = merkle_root(&hashes).map_err(|_| ClaimReject::Malformed)?;
    Ok((root, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(s: &str) -> ClaimId {
        ClaimId::from_signing_bytes(s.as_bytes())
    }

    fn targets() -> Vec<ReliesOn> {
        vec![
            ReliesOn {
                from_claim_id: cid("A"),
                kind: ReliesKind::IdentityBasis,
            },
            ReliesOn {
                from_claim_id: cid("B"),
                kind: ReliesKind::PriorCheck,
            },
        ]
    }

    #[test]
    fn kind_labels_are_stable_and_distinct() {
        let all = [
            ReliesKind::IdentityBasis,
            ReliesKind::PriorCheck,
            ReliesKind::Assessor,
            ReliesKind::Referee,
            ReliesKind::Renews,
            ReliesKind::Endorses,
        ];
        let labels: std::collections::BTreeSet<&str> = all.iter().map(|k| k.as_str()).collect();
        assert_eq!(labels.len(), 6, "kind labels must be distinct");
    }

    #[test]
    fn derived_salts_depend_on_index_and_master_salt_and_domain() {
        let m = [7u8; 32];
        assert_ne!(derive_reliance_salt(&m, 0), derive_reliance_salt(&m, 1)); // index
        assert_ne!(
            derive_reliance_salt(&m, 0),
            derive_reliance_salt(&[1u8; 32], 0)
        ); // master
        assert_eq!(derive_reliance_salt(&m, 0), derive_reliance_salt(&m, 0)); // deterministic
                                                                              // leaf salt and kind salt use different domains → different value at the same index
        assert_ne!(derive_reliance_salt(&m, 0), derive_kind_salt(&m, 0));
        // the kind salt itself must vary with index and master salt (never a constant)
        assert_ne!(derive_kind_salt(&m, 0), derive_kind_salt(&m, 1)); // index
        assert_ne!(derive_kind_salt(&m, 0), derive_kind_salt(&[1u8; 32], 0)); // master
    }

    #[test]
    fn kind_commit_hides_and_binds_the_kind() {
        let ks = [5u8; 32];
        let base = kind_commit(ReliesKind::IdentityBasis, &ks);
        assert_eq!(base, kind_commit(ReliesKind::IdentityBasis, &ks)); // deterministic
        assert_ne!(base, kind_commit(ReliesKind::Referee, &ks)); // binds the kind
        assert_ne!(base, kind_commit(ReliesKind::IdentityBasis, &[6u8; 32])); // hiding salt
    }

    #[test]
    fn h8_root_is_hiding_over_the_master_salt() {
        let (r1, c1) = reliance_commitment(&[1u8; 32], &targets()).unwrap();
        let (r2, c2) = reliance_commitment(&[2u8; 32], &targets()).unwrap();
        assert_eq!(c1, 2);
        assert_eq!(c2, 2);
        assert_ne!(
            r1, r2,
            "same targets, different master salt must not share a root"
        );
    }

    #[test]
    fn h7_reordering_targets_changes_the_root() {
        let m = [4u8; 32];
        let mut swapped = targets();
        swapped.swap(0, 1);
        assert_ne!(
            reliance_commitment(&m, &targets()).unwrap().0,
            reliance_commitment(&m, &swapped).unwrap().0,
            "reliance leaves are index-bound; a reorder must change the root"
        );
    }

    #[test]
    fn different_kind_at_same_position_changes_the_root() {
        let m = [4u8; 32];
        let mut other = targets();
        other[0].kind = ReliesKind::Referee;
        assert_ne!(
            reliance_commitment(&m, &targets()).unwrap().0,
            reliance_commitment(&m, &other).unwrap().0
        );
    }

    #[test]
    fn empty_reliance_uses_a_fixed_signed_sentinel() {
        let (root, count) = reliance_commitment(&[0u8; 32], &[]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(root, empty_reliance_root());
        assert_eq!(empty_reliance_root(), empty_reliance_root()); // fixed
                                                                  // …and a real domain-separated hash, never a trivial constant
        assert_ne!(empty_reliance_root(), [0u8; 32]);
        assert_ne!(empty_reliance_root(), [1u8; 32]);
        assert_ne!(
            root,
            reliance_commitment(&[0u8; 32], &targets()).unwrap().0,
            "the no-reliance sentinel must never equal a real commitment"
        );
    }

    #[test]
    fn single_target_count_is_one() {
        let one = vec![ReliesOn {
            from_claim_id: cid("solo"),
            kind: ReliesKind::Renews,
        }];
        let (_, count) = reliance_commitment(&[3u8; 32], &one).unwrap();
        assert_eq!(count, 1);
    }
}
