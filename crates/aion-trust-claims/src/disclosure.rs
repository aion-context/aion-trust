//! Field-level selective disclosure: the wire [`DisclosedClaim`] and its verified counterpart
//! [`VerifiedDisclosure`].
//!
//! A subject discloses a chosen *subset* of a claim's fields. Each [`RevealedField`] carries
//! its value, salt, and Merkle audit path; the issuer-signed `body_root` and `field_count` let
//! a verifier confirm every disclosed field belongs to the signed body — and, crucially,
//! detect a *maliciously omitted* field, because the full field set is a function of the
//! (signed) category. The typestate mirrors [`Claim`](crate::Claim) → `VerifiedClaim`: a
//! `DisclosedClaim` is untrusted, and only a successful [`DisclosedClaim::verify`] yields a
//! `VerifiedDisclosure` whose proven fields are safe to read.

use std::collections::BTreeMap;

use aion_context::crypto::VerifyingKey;
use aion_context::jcs::to_jcs_bytes;
use aion_trust_core::encoding::{decode_array, to_hex};
use aion_trust_core::merkle::{self, field_leaf_hash, root_from_path};
use aion_trust_core::{ClaimId, Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::bodies::ClaimBody;
use crate::claim::{signing_bytes, Claim, ClaimReject, Validity};
use crate::fields::BodyLeaf;

/// Which fields of a claim to disclose. [`FieldSelector::All`] is the claim-level default.
#[derive(Clone, Debug)]
pub enum FieldSelector {
    /// Disclose every field (each still proven against the root).
    All,
    /// Disclose only these field keys.
    Only(Vec<String>),
}

/// One revealed field with its Merkle proof — UNTRUSTED until [`DisclosedClaim::verify`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealedField {
    pub key: String,
    pub index: u32,
    pub salt: String,
    pub value: serde_json::Value,
    /// Sibling hashes from the leaf to the root, innermost first (hex).
    pub audit_path: Vec<String>,
}

/// The artifact a subject discloses: signed scalars + the committed root, plus a proof for
/// each revealed field. It carries **no body** — undisclosed fields appear nowhere.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosedClaim {
    pub claim_id: ClaimId,
    pub subject_id: Did,
    pub issuer_id: Did,
    pub validity: Validity,
    pub category: String,
    pub schema_id: String,
    pub body_root: String,
    pub field_count: u32,
    pub issuer_signature: String,
    fields: Vec<RevealedField>,
}

/// A field whose disclosure has been cryptographically proven. `Value` is the only case today;
/// marked `#[non_exhaustive]` so a future predicate-proof variant (a real range proof, when
/// `aion-context` gains one) can be added without breaking downstream matches.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ProvenField {
    Value(serde_json::Value),
}

/// A disclosure whose issuer signature and every revealed field's Merkle proof have checked
/// out. You can read **only** the fields that were proven; there is no `body()`.
#[must_use = "a verified disclosure carries a trust decision; dropping it discards the check"]
pub struct VerifiedDisclosure {
    claim_id: ClaimId,
    subject_id: Did,
    issuer_id: Did,
    validity: Validity,
    category: String,
    fields: BTreeMap<String, ProvenField>,
}

impl DisclosedClaim {
    /// Build a disclosure from a full claim, its precomputed leaves, and a selector. Called
    /// only by [`Claim::disclose`] (the sole body-touching point). Defensive: an empty or
    /// unknown selection is a `Malformed` reject.
    pub(crate) fn build(
        claim: &Claim,
        leaves: &[BodyLeaf],
        selector: &FieldSelector,
    ) -> Result<DisclosedClaim, ClaimReject> {
        let indices = selected_indices(leaves, selector)?;
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
        let mut fields = Vec::with_capacity(indices.len());
        for pos in indices {
            let leaf = leaves.get(pos).ok_or(ClaimReject::Malformed)?;
            let path = merkle::audit_path(&hashes, pos).map_err(|_| ClaimReject::Malformed)?;
            fields.push(RevealedField {
                key: leaf.key.clone(),
                index: u32::try_from(pos).map_err(|_| ClaimReject::Malformed)?,
                salt: to_hex(&leaf.salt),
                value: leaf.value.clone(),
                audit_path: path.iter().map(|h| to_hex(h)).collect(),
            });
        }
        Ok(DisclosedClaim {
            claim_id: claim.claim_id.clone(),
            subject_id: claim.subject_id.clone(),
            issuer_id: claim.issuer_id.clone(),
            validity: claim.validity.clone(),
            category: claim.category().to_string(),
            schema_id: claim.schema_id().to_string(),
            body_root: claim.body_root.clone(),
            field_count: claim.field_count,
            issuer_signature: claim.issuer_signature.clone(),
            fields,
        })
    }

    pub fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }
    pub fn subject_id(&self) -> &Did {
        &self.subject_id
    }
    pub fn issuer_id(&self) -> &Did {
        &self.issuer_id
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    /// The keys disclosed (untrusted — for routing only; trust the verified set instead).
    pub fn disclosed_keys(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|f| f.key.as_str())
    }

    /// Verify authenticity and every field's Merkle proof, requiring no particular field.
    pub fn verify(&self, issuer_vk: &VerifyingKey) -> Result<VerifiedDisclosure, ClaimReject> {
        self.verify_with_required(issuer_vk, &[])
    }

    /// As [`Self::verify`], but also reject unless every key in `required` was disclosed —
    /// the verifier's defense against a maliciously omitted field.
    pub fn verify_with_required(
        &self,
        issuer_vk: &VerifyingKey,
        required: &[&str],
    ) -> Result<VerifiedDisclosure, ClaimReject> {
        let body_root = self.check_signature(issuer_vk)?;
        let expected =
            ClaimBody::field_keys_for_category(&self.category).ok_or(ClaimReject::Malformed)?;
        // The signed tree must have exactly the schema's fields, so a missing field is visible.
        if self.field_count as usize != expected.len() {
            return Err(ClaimReject::BodyTampered);
        }
        let mut proven = BTreeMap::new();
        for f in &self.fields {
            self.prove_field(f, expected, &body_root)?;
            proven.insert(f.key.clone(), ProvenField::Value(f.value.clone()));
        }
        for key in required {
            if !proven.contains_key(*key) {
                return Err(ClaimReject::MissingField);
            }
        }
        Ok(VerifiedDisclosure {
            claim_id: self.claim_id.clone(),
            subject_id: self.subject_id.clone(),
            issuer_id: self.issuer_id.clone(),
            validity: self.validity.clone(),
            category: self.category.clone(),
            fields: proven,
        })
    }

    /// Check the issuer key, reconstruct the signed message from the signed scalars (no body
    /// needed), and verify the claim_id and signature. Returns the decoded `body_root`.
    fn check_signature(&self, issuer_vk: &VerifyingKey) -> Result<[u8; 32], ClaimReject> {
        if Did::from_key(issuer_vk) != self.issuer_id {
            return Err(ClaimReject::IssuerKeyMismatch);
        }
        let body_root = decode_array::<32>(&self.body_root).map_err(|_| ClaimReject::Malformed)?;
        let signing = signing_bytes(
            &self.subject_id,
            &self.issuer_id,
            &self.category,
            &self.schema_id,
            &self.validity,
            &body_root,
            self.field_count,
        );
        if ClaimId::from_signing_bytes(&signing) != self.claim_id {
            return Err(ClaimReject::ClaimIdMismatch);
        }
        let sig = decode_array::<64>(&self.issuer_signature).map_err(|_| ClaimReject::Malformed)?;
        issuer_vk
            .verify(&signing, &sig)
            .map_err(|_| ClaimReject::BadSignature)?;
        Ok(body_root)
    }

    /// Prove one revealed field: its key must match the schema field at its index, and its
    /// leaf must recompute the signed `body_root` via the audit path.
    fn prove_field(
        &self,
        f: &RevealedField,
        expected: &[&str],
        body_root: &[u8; 32],
    ) -> Result<(), ClaimReject> {
        let idx = usize::try_from(f.index).map_err(|_| ClaimReject::Malformed)?;
        let expected_key = expected.get(idx).ok_or(ClaimReject::BodyTampered)?;
        if *expected_key != f.key {
            return Err(ClaimReject::BodyTampered);
        }
        let salt = decode_array::<32>(&f.salt).map_err(|_| ClaimReject::Malformed)?;
        let jcs = to_jcs_bytes(&f.value).map_err(|_| ClaimReject::Malformed)?;
        let leaf = field_leaf_hash(f.index, &f.key, &salt, &jcs);
        let path = decode_path(&f.audit_path)?;
        let root = root_from_path(leaf, idx, self.field_count as usize, &path)
            .map_err(|_| ClaimReject::BodyTampered)?;
        if &root != body_root {
            return Err(ClaimReject::BodyTampered);
        }
        Ok(())
    }
}

impl VerifiedDisclosure {
    pub fn claim_id(&self) -> &ClaimId {
        &self.claim_id
    }
    pub fn subject_id(&self) -> &Did {
        &self.subject_id
    }
    pub fn issuer_id(&self) -> &Did {
        &self.issuer_id
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn active_at(&self, now: Timestamp) -> bool {
        self.validity.active_at(now)
    }
    /// The proven fields, by key.
    pub fn fields(&self) -> &BTreeMap<String, ProvenField> {
        &self.fields
    }
    /// The proven value for a field, if it was disclosed as a value.
    pub fn value(&self, key: &str) -> Option<&serde_json::Value> {
        match self.fields.get(key) {
            Some(ProvenField::Value(v)) => Some(v),
            None => None,
        }
    }
    /// The keys proven in this disclosure.
    pub fn revealed_keys(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }
}

/// Resolve a selector to a list of leaf indices, erroring on an empty or unknown selection.
fn selected_indices(
    leaves: &[BodyLeaf],
    selector: &FieldSelector,
) -> Result<Vec<usize>, ClaimReject> {
    match selector {
        FieldSelector::All => Ok((0..leaves.len()).collect()),
        FieldSelector::Only(keys) => {
            if keys.is_empty() {
                return Err(ClaimReject::Malformed);
            }
            let mut indices = Vec::with_capacity(keys.len());
            for key in keys {
                let pos = leaves
                    .iter()
                    .position(|l| &l.key == key)
                    .ok_or(ClaimReject::Malformed)?;
                indices.push(pos);
            }
            Ok(indices)
        }
    }
}

fn decode_path(hexes: &[String]) -> Result<Vec<[u8; 32]>, ClaimReject> {
    let mut path = Vec::with_capacity(hexes.len());
    for h in hexes {
        path.push(decode_array::<32>(h).map_err(|_| ClaimReject::Malformed)?);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::EmploymentBody;
    use aion_context::crypto::VerifyingKey;
    use aion_trust_core::Identity;

    fn issue() -> (Identity, VerifyingKey, Claim) {
        let issuer = Identity::generate();
        let vk = issuer.verifying_key();
        let subject = Identity::generate().did();
        let body = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021".into(),
            end: None,
            rehire_eligible: false,
        });
        let validity = Validity {
            from: Timestamp(0),
            until: None,
        };
        let claim = Claim::issue(&issuer, &subject, validity, body).unwrap();
        (issuer, vk, claim)
    }

    #[test]
    fn numeric_and_non_ascii_field_values_round_trip_through_jcs() {
        // The leaf hash is over to_jcs_bytes(value) at BOTH issue and verify. Pin that a
        // numeric ordinal and a non-ASCII string survive that round-trip identically, so the
        // proof still recomputes the signed root (guards a future JCS regression).
        let issuer = Identity::generate();
        let subject = Identity::generate().did();
        let body = ClaimBody::Education(crate::bodies::EducationBody {
            institution: "Universität Zürich".into(),
            credential: "Doctorat ès sciences — 北京".into(),
            conferred: "2020".into(),
            aion_edu_ref: None,
            degree_rank: Some(5),
        });
        let claim = Claim::issue(
            &issuer,
            &subject,
            Validity {
                from: Timestamp(0),
                until: None,
            },
            body,
        )
        .unwrap();
        let v = claim
            .disclose(&FieldSelector::All)
            .unwrap()
            .verify(&issuer.verifying_key())
            .unwrap();
        assert_eq!(v.value("degree_rank"), Some(&serde_json::json!(5)));
        assert_eq!(
            v.value("credential"),
            Some(&serde_json::json!("Doctorat ès sciences — 北京"))
        );
    }

    #[test]
    fn full_disclosure_round_trips() {
        let (_, vk, claim) = issue();
        let d = claim.disclose(&FieldSelector::All).unwrap();
        assert_eq!(d.category(), "employment"); // pins DisclosedClaim::category
        let wire_keys: Vec<&str> = d.disclosed_keys().collect(); // pins disclosed_keys
        assert_eq!(
            wire_keys,
            [
                "employer",
                "employment_type",
                "end",
                "rehire_eligible",
                "start",
                "title"
            ]
        );
        let v = d.verify(&vk).unwrap();
        assert_eq!(v.category(), "employment"); // pins VerifiedDisclosure::category
        let keys: Vec<&str> = v.revealed_keys().collect();
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
        assert_eq!(v.value("title"), Some(&serde_json::json!("Engineer")));
        // pins VerifiedDisclosure::fields — the proven map holds the six fields
        assert_eq!(v.fields().len(), 6);
        assert!(v.fields().contains_key("title"));
    }

    #[test]
    fn partial_disclosure_proves_only_the_subset() {
        let (_, vk, claim) = issue();
        let d = claim
            .disclose(&FieldSelector::Only(vec![
                "employer".into(),
                "title".into(),
            ]))
            .unwrap();
        let v = d.verify(&vk).unwrap();
        let keys: Vec<&str> = v.revealed_keys().collect();
        assert_eq!(keys, ["employer", "title"]); // BTreeMap → sorted
        assert_eq!(v.value("employer"), Some(&serde_json::json!("Acme")));
        assert_eq!(v.value("rehire_eligible"), None); // withheld
    }

    #[test]
    fn wrong_issuer_key_is_rejected() {
        let (_, _, claim) = issue();
        let other = Identity::generate().verifying_key();
        let d = claim.disclose(&FieldSelector::All).unwrap();
        assert_eq!(d.verify(&other).err(), Some(ClaimReject::IssuerKeyMismatch));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        d.issuer_signature = d.issuer_signature.chars().rev().collect();
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::BadSignature));
    }

    #[test]
    fn tampered_scalar_breaks_claim_id() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        d.subject_id = Did::from_string("did:aion:someone-else".into());
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::ClaimIdMismatch));
    }

    #[test]
    fn tampered_field_value_is_rejected() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        d.fields[0].value = serde_json::json!("Globex");
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::BodyTampered));
    }

    #[test]
    fn key_not_matching_its_index_is_rejected() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        // claim a value belongs to a different field name than its index
        d.fields[0].key = "title".into();
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::BodyTampered));
    }

    #[test]
    fn wrong_index_is_rejected() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        d.fields[0].index = 5; // not its real position
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::BodyTampered));
    }

    #[test]
    fn tampered_audit_path_is_rejected() {
        let (_, vk, claim) = issue();
        let mut d = claim.disclose(&FieldSelector::All).unwrap();
        let sibling = &mut d.fields[0].audit_path[0];
        *sibling = sibling.chars().rev().collect();
        assert_eq!(d.verify(&vk).err(), Some(ClaimReject::BodyTampered));
    }

    #[test]
    fn omitted_required_field_is_detected() {
        let (_, vk, claim) = issue();
        let d = claim
            .disclose(&FieldSelector::Only(vec!["title".into()]))
            .unwrap();
        // requiring a field that was disclosed passes; one that was withheld fails
        assert!(d.verify_with_required(&vk, &["title"]).is_ok());
        assert_eq!(
            d.verify_with_required(&vk, &["rehire_eligible"]).err(),
            Some(ClaimReject::MissingField)
        );
    }

    #[test]
    fn field_count_disagreeing_with_schema_is_rejected() {
        // Forge a validly-signed disclosure whose field_count disagrees with the category's
        // true field set — the defense that a tree cannot have fewer leaves than the schema.
        let (issuer, vk, claim) = issue();
        let d = claim.disclose(&FieldSelector::All).unwrap();
        let body_root = decode_array::<32>(&d.body_root).unwrap();
        let bogus_count = d.field_count + 1;
        let signing = signing_bytes(
            &d.subject_id,
            &d.issuer_id,
            &d.category,
            &d.schema_id,
            &d.validity,
            &body_root,
            bogus_count,
        );
        let forged = DisclosedClaim {
            claim_id: ClaimId::from_signing_bytes(&signing),
            field_count: bogus_count,
            issuer_signature: to_hex(&issuer.sign(&signing)),
            ..d
        };
        assert_eq!(forged.verify(&vk).err(), Some(ClaimReject::BodyTampered));
    }
}
