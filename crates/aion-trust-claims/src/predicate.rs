//! Predicate proofs over selectively-disclosed fields.
//!
//! **This is data minimization, NOT zero-knowledge.** `aion-context` has no range/ZK
//! primitive and invariant #4 forbids hand-rolling one, so a predicate is answered by
//! disclosing the *minimal* field that settles it — an issuer-attested coarse attribute (a
//! `degree_rank`, a date) — and the verifier evaluates the comparison over that
//! Merkle-proven, issuer-signed value. It hides every *other* field of the claim, but it does
//! **not** hide the disclosed attribute itself, and equal attributes are linkable across
//! presentations. When `aion-context` gains a real range proof, the same [`PredicateRequest`]
//! plumbing can carry it without a wire change.
//!
//! Soundness rests on two rules the verifier enforces (see `presentation`): a predicate is
//! evaluated **only** over a claim that already passed authenticity, accreditation,
//! revocation, and validity (so it can only *narrow* acceptance, never grant it); and the
//! ordinal scale is **issuer-attested** and schema-pinned — the verifier never infers a rank
//! from free text, and a scale-version mismatch fails closed.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::claim::ClaimReject;

/// A comparison operator for a predicate over a single disclosed field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOp {
    Ge,
    Le,
    Gt,
    Lt,
    Eq,
}

/// A verifier's predicate: "a claim of `category` proves its `field` `op` `bound`". For an
/// ordinal field, `scale_version` pins the schema whose ordinal scale both sides reference; the
/// verifier fails closed if a matched claim's `schema_id` differs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PredicateRequest {
    pub category: String,
    pub field: String,
    pub op: PredicateOp,
    pub bound: serde_json::Value,
    #[serde(default)]
    pub scale_version: Option<String>,
}

impl PredicateRequest {
    /// A short, stable label for verification reports.
    pub fn label(&self) -> String {
        format!("{} {:?} {}", self.field, self.op, self.bound)
    }
}

/// Evaluate `value op bound`. Both must be the same comparable kind (integer, float, or
/// string); a type mismatch is a [`ClaimReject::Malformed`] so a predicate can never silently
/// pass on incomparable inputs.
pub fn evaluate(
    op: PredicateOp,
    value: &serde_json::Value,
    bound: &serde_json::Value,
) -> Result<bool, ClaimReject> {
    let ord = compare(value, bound)?;
    Ok(match op {
        PredicateOp::Ge => ord != Ordering::Less,
        PredicateOp::Gt => ord == Ordering::Greater,
        PredicateOp::Le => ord != Ordering::Greater,
        PredicateOp::Lt => ord == Ordering::Less,
        PredicateOp::Eq => ord == Ordering::Equal,
    })
}

/// Total comparison over JSON scalars: integers, then floats, then strings (lexical — ISO-8601
/// dates order correctly). Anything else is a type mismatch.
fn compare(a: &serde_json::Value, b: &serde_json::Value) -> Result<Ordering, ClaimReject> {
    if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
        return Ok(x.cmp(&y));
    }
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return x.partial_cmp(&y).ok_or(ClaimReject::Malformed);
    }
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return Ok(x.cmp(y));
    }
    Err(ClaimReject::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn integer_ordering_and_boundaries() {
        // degree_rank >= 3 : master(4) yes, bachelor(3) yes (boundary), associate(2) no
        assert!(evaluate(PredicateOp::Ge, &json!(4), &json!(3)).unwrap());
        assert!(evaluate(PredicateOp::Ge, &json!(3), &json!(3)).unwrap()); // inclusive boundary
        assert!(!evaluate(PredicateOp::Ge, &json!(2), &json!(3)).unwrap());
        assert!(evaluate(PredicateOp::Gt, &json!(4), &json!(3)).unwrap());
        assert!(!evaluate(PredicateOp::Gt, &json!(3), &json!(3)).unwrap()); // strict
        assert!(evaluate(PredicateOp::Lt, &json!(2), &json!(3)).unwrap());
        assert!(evaluate(PredicateOp::Le, &json!(3), &json!(3)).unwrap());
        assert!(evaluate(PredicateOp::Eq, &json!(3), &json!(3)).unwrap());
        assert!(!evaluate(PredicateOp::Eq, &json!(3), &json!(4)).unwrap());
    }

    #[test]
    fn iso_date_strings_order_lexically() {
        // "check performed on/after 2025-06-21" — recency as a date comparison
        assert!(evaluate(PredicateOp::Ge, &json!("2026-05-10"), &json!("2025-06-21")).unwrap());
        assert!(!evaluate(PredicateOp::Ge, &json!("2024-01-01"), &json!("2025-06-21")).unwrap());
        assert!(evaluate(PredicateOp::Ge, &json!("2025-06-21"), &json!("2025-06-21")).unwrap());
    }

    #[test]
    fn type_mismatch_is_rejected_not_silently_passed() {
        assert_eq!(
            evaluate(PredicateOp::Ge, &json!("bachelor"), &json!(3)),
            Err(ClaimReject::Malformed)
        );
        assert_eq!(
            evaluate(PredicateOp::Ge, &json!(true), &json!(false)),
            Err(ClaimReject::Malformed)
        );
    }

    #[test]
    fn label_is_descriptive() {
        let req = PredicateRequest {
            category: "education".into(),
            field: "degree_rank".into(),
            op: PredicateOp::Ge,
            bound: json!(3),
            scale_version: None,
        };
        assert!(req.label().contains("degree_rank"));
    }
}
