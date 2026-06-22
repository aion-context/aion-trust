//! A salted-field Merkle commitment, the foundation of field-level selective disclosure.
//!
//! A claim body is committed not as one hash but as a Merkle root over its fields: each field
//! is a salted leaf, and the issuer signs the root. A subject can then reveal a *subset* of
//! fields — each proven against the signed root by an audit path — while the undisclosed
//! fields contribute only their sibling hashes and stay hidden.
//!
//! This is **composition over `aion-context`'s BLAKE3**, not hand-rolled cryptography: leaves
//! and nodes are `crypto::hash` of domain-separated, length-prefixed [`SigningWriter`] bytes.
//! The tree shape mirrors RFC 6962 (the same split-point recursion `aion-context`'s
//! transparency log uses) but with this crate's own leaf/node domains, so a field commitment
//! can never collide with a log entry, and a leaf hash can never equal an internal node hash.

use aion_context::crypto;

use crate::encoding::SigningWriter;

/// Domain tag for field leaves. Distinct from [`FIELD_NODE_DOMAIN`] so a leaf and an internal
/// node can never hash to the same value (the RFC 6962 leaf/node second-preimage defense).
pub const FIELD_LEAF_DOMAIN: &[u8] = b"aion-trust/claim-field-leaf/v1";
/// Domain tag for internal nodes.
pub const FIELD_NODE_DOMAIN: &[u8] = b"aion-trust/claim-field-node/v1";

/// Why a Merkle operation failed. Kept local (not [`crate::TrustError`]) so this module stays
/// free of claim-domain semantics; callers map it at their boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// A root or path was requested over zero leaves. A claim body always has ≥ 1 field.
    Empty,
    /// The leaf index is not less than the leaf count.
    IndexOutOfRange,
    /// The audit path is the wrong length for `(index, count)`.
    MalformedPath,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MerkleError::Empty => "merkle tree has no leaves",
            MerkleError::IndexOutOfRange => "leaf index out of range",
            MerkleError::MalformedPath => "audit path is the wrong length",
        };
        f.write_str(s)
    }
}

impl std::error::Error for MerkleError {}

/// The hash of one field leaf, binding its position, name, salt, and canonical value. Built
/// with [`SigningWriter`] (length-prefixed, domain-tagged) so no two distinct
/// `(index, key, salt, value)` tuples can ever encode to the same preimage.
pub fn field_leaf_hash(index: u32, key: &str, salt: &[u8; 32], jcs_value: &[u8]) -> [u8; 32] {
    let mut w = SigningWriter::new(FIELD_LEAF_DOMAIN);
    w.u32(index)
        .field(key.as_bytes())
        .field(salt)
        .field(jcs_value);
    crypto::hash(&w.into_bytes())
}

/// Hash an internal node over its two children, under the node domain.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut w = SigningWriter::new(FIELD_NODE_DOMAIN);
    w.field(left).field(right);
    crypto::hash(&w.into_bytes())
}

/// Largest power of two strictly less than `n` (the RFC 6962 split point). Only ever called
/// with `n >= 2`, where the result is in `1..n`.
const fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

/// The Merkle root over `leaves` (each already a leaf hash), in order.
///
/// # Errors
/// [`MerkleError::Empty`] if `leaves` is empty.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    Ok(mth(leaves))
}

/// Merkle Tree Hash of a non-empty slice. Both halves of every split are non-empty (because
/// `split_point` returns a value in `1..len` for `len >= 2`), so recursion never sees `[]`.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if let [single] = leaves {
        return *single;
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at(k);
    node_hash(&mth(left), &mth(right))
}

/// The audit path for the leaf at `index`: sibling hashes from the leaf up to the root,
/// **innermost first** (matching [`root_from_path`]).
///
/// # Errors
/// [`MerkleError::Empty`] if `leaves` is empty; [`MerkleError::IndexOutOfRange`] if
/// `index >= leaves.len()`.
pub fn audit_path(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange);
    }
    Ok(path(leaves, index))
}

/// Innermost-first sibling collection. Pushes the outer sibling last so the path is consumed
/// outermost-last by [`root_from_path`].
fn path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at(k);
    if index < k {
        let mut p = path(left, index);
        p.push(mth(right));
        p
    } else {
        let mut p = path(right, index - k);
        p.push(mth(left));
        p
    }
}

/// Recompute the root from a leaf, its index, the tree's leaf `count`, and its audit path.
/// A verifier compares the result against the issuer-signed root.
///
/// # Errors
/// [`MerkleError::Empty`] / [`MerkleError::IndexOutOfRange`] / [`MerkleError::MalformedPath`]
/// for a zero count, an out-of-range index, or a path of the wrong length.
pub fn root_from_path(
    leaf: [u8; 32],
    index: usize,
    count: usize,
    path: &[[u8; 32]],
) -> Result<[u8; 32], MerkleError> {
    if count == 0 {
        return Err(MerkleError::Empty);
    }
    if index >= count {
        return Err(MerkleError::IndexOutOfRange);
    }
    if count == 1 {
        return if path.is_empty() {
            Ok(leaf)
        } else {
            Err(MerkleError::MalformedPath)
        };
    }
    let (&outer, inner) = path.split_last().ok_or(MerkleError::MalformedPath)?;
    let k = split_point(count);
    if index < k {
        let left = root_from_path(leaf, index, k, inner)?;
        Ok(node_hash(&left, &outer))
    } else {
        let right = root_from_path(leaf, index - k, count - k, inner)?;
        Ok(node_hash(&outer, &right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf(i as u8)).collect()
    }

    /// Independent, non-cached reference MTH — a second implementation so a bug in `mth`
    /// cannot hide behind itself.
    fn reference_root(ls: &[[u8; 32]]) -> [u8; 32] {
        if ls.len() == 1 {
            return ls[0];
        }
        let mut k = 1;
        while k * 2 < ls.len() {
            k *= 2;
        }
        node_hash(&reference_root(&ls[..k]), &reference_root(&ls[k..]))
    }

    #[test]
    fn empty_is_rejected_everywhere() {
        assert_eq!(merkle_root(&[]), Err(MerkleError::Empty));
        assert_eq!(audit_path(&[], 0), Err(MerkleError::Empty));
        assert_eq!(root_from_path(leaf(0), 0, 0, &[]), Err(MerkleError::Empty));
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        assert_eq!(merkle_root(&[leaf(7)]).unwrap(), leaf(7));
        // a single-leaf tree has an empty path, and a non-empty path is malformed
        assert_eq!(audit_path(&[leaf(7)], 0).unwrap(), Vec::<[u8; 32]>::new());
        assert_eq!(root_from_path(leaf(7), 0, 1, &[]).unwrap(), leaf(7));
        assert_eq!(
            root_from_path(leaf(7), 0, 1, &[leaf(9)]),
            Err(MerkleError::MalformedPath)
        );
    }

    #[test]
    fn two_leaf_root_is_node_of_both() {
        let ls = leaves(2);
        assert_eq!(merkle_root(&ls).unwrap(), node_hash(&ls[0], &ls[1]));
    }

    #[test]
    fn leaf_and_node_domains_are_separated() {
        // same 64 bytes, different role → different hash (no leaf/node confusion)
        let a = leaf(1);
        let b = leaf(2);
        let as_node = node_hash(&a, &b);
        let mut w = SigningWriter::new(FIELD_LEAF_DOMAIN);
        w.field(&a).field(&b);
        let as_leafish = crypto::hash(&w.into_bytes());
        assert_ne!(as_node, as_leafish);
    }

    #[test]
    fn field_leaf_hash_binds_every_input() {
        let s = [3u8; 32];
        let base = field_leaf_hash(0, "k", &s, b"v");
        assert_ne!(base, field_leaf_hash(1, "k", &s, b"v")); // index
        assert_ne!(base, field_leaf_hash(0, "j", &s, b"v")); // key
        assert_ne!(base, field_leaf_hash(0, "k", &[4u8; 32], b"v")); // salt
        assert_ne!(base, field_leaf_hash(0, "k", &s, b"w")); // value
                                                             // length-prefixing prevents the (key,value) boundary slide
        assert_ne!(
            field_leaf_hash(0, "ab", &s, b"c"),
            field_leaf_hash(0, "a", &s, b"bc")
        );
    }

    #[test]
    fn root_matches_independent_reference_for_every_size() {
        for n in 1..=64 {
            let ls = leaves(n);
            assert_eq!(merkle_root(&ls).unwrap(), reference_root(&ls), "n={n}");
        }
    }

    #[test]
    fn every_index_path_recomputes_the_root() {
        for n in 1..=64 {
            let ls = leaves(n);
            let root = merkle_root(&ls).unwrap();
            for i in 0..n {
                let p = audit_path(&ls, i).unwrap();
                assert_eq!(
                    root_from_path(ls[i], i, n, &p).unwrap(),
                    root,
                    "n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn audit_path_rejects_out_of_range_index() {
        let ls = leaves(5);
        assert_eq!(audit_path(&ls, 5), Err(MerkleError::IndexOutOfRange));
        assert_eq!(
            root_from_path(ls[0], 5, 5, &[]),
            Err(MerkleError::IndexOutOfRange)
        );
    }

    #[test]
    fn tampered_leaf_index_sibling_or_length_all_reject() {
        let ls = leaves(8);
        let root = merkle_root(&ls).unwrap();
        let p = audit_path(&ls, 3).unwrap();
        // a wrong leaf does not recompute the root
        assert_ne!(root_from_path(leaf(99), 3, 8, &p).unwrap(), root);
        // a wrong (but in-range) index does not recompute the root
        assert_ne!(root_from_path(ls[3], 4, 8, &p).unwrap(), root);
        // a tampered sibling does not recompute the root
        let mut bad = p.clone();
        bad[0] = leaf(99);
        assert_ne!(root_from_path(ls[3], 3, 8, &bad).unwrap(), root);
        // a path of the wrong length is malformed (count=8 needs depth 3)
        let mut short = p.clone();
        short.pop();
        assert_eq!(
            root_from_path(ls[3], 3, 8, &short),
            Err(MerkleError::MalformedPath)
        );
        let mut long = p.clone();
        long.push(leaf(1));
        assert_eq!(
            root_from_path(ls[3], 3, 8, &long),
            Err(MerkleError::MalformedPath)
        );
    }

    #[test]
    fn merkle_error_display_is_distinct() {
        assert_ne!(
            MerkleError::Empty.to_string(),
            MerkleError::IndexOutOfRange.to_string()
        );
        assert_ne!(
            MerkleError::IndexOutOfRange.to_string(),
            MerkleError::MalformedPath.to_string()
        );
    }
}
