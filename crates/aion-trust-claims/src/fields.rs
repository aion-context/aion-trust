//! Decomposing a claim body into its salted Merkle leaves — the bridge between [`ClaimBody`]
//! and [`aion_trust_core::merkle`].
//!
//! A body's fields become an ordered list of leaves in **JCS key order** (the internal
//! `claim_type` serde tag excluded — the category is a signed scalar, not a disclosable
//! field). Each field's salt is *derived* from one per-claim master salt, so the wallet stores
//! a single secret yet every field gets an independent, hiding salt: revealing one disclosed
//! field's salt tells an attacker nothing about the withheld fields (BLAKE3-keyed PRF). This
//! is the one place that turns the typed body into leaves; both issuing and disclosure use it,
//! so the issuer-signed root and a later disclosure are always computed the same way.

use std::collections::BTreeMap;

use aion_context::crypto::keyed_hash;
use aion_context::jcs::to_jcs_bytes;
use aion_trust_core::encoding::SigningWriter;
use aion_trust_core::merkle::{self, field_leaf_hash};

use crate::bodies::ClaimBody;
use crate::claim::ClaimReject;

/// The serde tag injected by `#[serde(tag = "claim_type")]`. Excluded from the leaf set: the
/// category is already bound as a signed scalar, and it must not be an omittable field.
const CLAIM_TYPE_TAG: &str = "claim_type";

/// One field of a body, decomposed into everything needed to commit it or disclose it.
pub(crate) struct BodyLeaf {
    pub key: String,
    pub value: serde_json::Value,
    pub salt: [u8; 32],
    pub hash: [u8; 32],
}

/// Derive the per-field salt: `keyed_hash(master_salt, domain || index || key)`. Deterministic
/// from the master salt, independent across fields, and one-way (revealing it leaks neither
/// the master salt nor any sibling salt).
fn derive_field_salt(master_salt: &[u8; 32], index: u32, key: &str) -> [u8; 32] {
    let mut w = SigningWriter::new(merkle::FIELD_LEAF_DOMAIN);
    w.u32(index).field(key.as_bytes());
    keyed_hash(master_salt, &w.into_bytes())
}

/// The body's fields in canonical (JCS key) order — the stable index assignment leaves rely
/// on. Collected through a [`BTreeMap`] so ordering never depends on `serde_json`'s feature
/// flags; for the ASCII field keys used here, byte order equals JCS UTF-16 order.
fn ordered_fields(body: &ClaimBody) -> Result<Vec<(String, serde_json::Value)>, ClaimReject> {
    let value = serde_json::to_value(body).map_err(|_| ClaimReject::Malformed)?;
    let serde_json::Value::Object(map) = value else {
        return Err(ClaimReject::Malformed);
    };
    let sorted: BTreeMap<String, serde_json::Value> = map
        .into_iter()
        .filter(|(k, _)| k != CLAIM_TYPE_TAG)
        .collect();
    Ok(sorted.into_iter().collect())
}

/// Decompose a body into its ordered, salted leaves under `master_salt`. The single source of
/// truth for both `Claim::issue` (which Merkleizes the hashes) and disclosure (which needs the
/// values, salts, and audit paths).
pub(crate) fn body_leaves(
    master_salt: &[u8; 32],
    body: &ClaimBody,
) -> Result<Vec<BodyLeaf>, ClaimReject> {
    let fields = ordered_fields(body)?;
    let mut leaves = Vec::with_capacity(fields.len());
    for (index, (key, value)) in fields.into_iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| ClaimReject::Malformed)?;
        let jcs_value = to_jcs_bytes(&value).map_err(|_| ClaimReject::Malformed)?;
        let salt = derive_field_salt(master_salt, index, &key);
        let hash = field_leaf_hash(index, &key, &salt, &jcs_value);
        leaves.push(BodyLeaf {
            key,
            value,
            salt,
            hash,
        });
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::{EmploymentBody, SkillBody};

    fn employment() -> ClaimBody {
        ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021".into(),
            end: None,
            rehire_eligible: true,
        })
    }

    #[test]
    fn fields_are_sorted_and_exclude_the_type_tag() {
        let fields = ordered_fields(&employment()).unwrap();
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "employer",
                "employment_type",
                "end",
                "rehire_eligible",
                "start",
                "title"
            ]
        );
        assert!(!keys.contains(&CLAIM_TYPE_TAG));
        // sorted == its own sorted copy
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn derived_salt_depends_on_index_and_key() {
        let m = [9u8; 32];
        let base = derive_field_salt(&m, 0, "k");
        assert_ne!(base, derive_field_salt(&m, 1, "k")); // index
        assert_ne!(base, derive_field_salt(&m, 0, "j")); // key
        assert_ne!(base, derive_field_salt(&[1u8; 32], 0, "k")); // master salt
        assert_eq!(base, derive_field_salt(&m, 0, "k")); // deterministic
    }

    #[test]
    fn body_leaves_hashes_match_field_leaf_hash() {
        let m = [5u8; 32];
        let leaves = body_leaves(&m, &employment()).unwrap();
        assert_eq!(leaves.len(), 6);
        for (i, l) in leaves.iter().enumerate() {
            let jcs = to_jcs_bytes(&l.value).unwrap();
            let expected = field_leaf_hash(i as u32, &l.key, &l.salt, &jcs);
            assert_eq!(l.hash, expected);
        }
    }

    #[test]
    fn an_option_none_field_still_appears_as_a_leaf() {
        // `end: None` must still be a leaf (serialized as null) — a stable field set is what
        // lets a verifier detect a maliciously omitted field.
        let m = [2u8; 32];
        let leaves = body_leaves(&m, &employment()).unwrap();
        let end = leaves.iter().find(|l| l.key == "end").unwrap();
        assert_eq!(end.value, serde_json::Value::Null);
    }

    #[test]
    fn skill_body_has_two_ordered_leaves() {
        let m = [1u8; 32];
        let body = ClaimBody::Skill(SkillBody {
            skill: "Rust".into(),
            level: None,
        });
        let leaves = body_leaves(&m, &body).unwrap();
        let keys: Vec<&str> = leaves.iter().map(|l| l.key.as_str()).collect();
        assert_eq!(keys, ["level", "skill"]);
    }

    /// The hand-written `field_keys_for_category` lists must equal what serialization actually
    /// produces — for every category. This couples the declared field set to the source of
    /// truth, so any field add/remove/rename breaks the build until both agree.
    #[test]
    fn field_keys_match_serialization() {
        let m = [0u8; 32];
        for (body, category, _) in crate::bodies::tests::one_of_each() {
            let leaves = body_leaves(&m, &body).unwrap();
            let got: Vec<&str> = leaves.iter().map(|l| l.key.as_str()).collect();
            let declared = ClaimBody::field_keys_for_category(category).unwrap();
            assert_eq!(got, declared, "{category} field set drifted");
        }
    }

    /// The field *set* must not change with `Option` contents — an absent field still
    /// serializes (as null), so it is still a leaf. If anyone adds `skip_serializing_if`, the
    /// key set would shrink and this gate fails (which is the point: omission must be visible).
    #[test]
    fn field_set_is_independent_of_option_contents() {
        let m = [0u8; 32];
        let some = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021".into(),
            end: Some("2024".into()),
            rehire_eligible: true,
        });
        let none = employment(); // identical but end: None
        let some_keys: Vec<String> = body_leaves(&m, &some)
            .unwrap()
            .into_iter()
            .map(|l| l.key)
            .collect();
        let none_keys: Vec<String> = body_leaves(&m, &none)
            .unwrap()
            .into_iter()
            .map(|l| l.key)
            .collect();
        assert_eq!(some_keys, none_keys);
    }
}
