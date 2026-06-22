//! aion-trust-wallet — the subject's side of the system.
//!
//! A [`Wallet`] holds the subject's cryptographic [`Identity`] and their **Trust Profile**:
//! every claim they have been issued. From it the subject builds a minimized, audience-bound
//! [`Presentation`] — the artifact that replaces the résumé. The wallet is the only place the
//! PII-bearing claim bodies live; nothing here ever touches a shared ledger.

use std::path::Path;

use aion_trust_claims::{
    build_presentation, evaluate_predicate, Claim, ClaimBody, ClaimReject, DisclosedClaim,
    FieldSelector, PredicateRequest, Presentation,
};
use aion_trust_core::encoding::{decode_array, from_hex, to_hex};
use aion_trust_core::{Did, Identity, Result, Timestamp};
use serde::{Deserialize, Serialize};

/// One claim to disclose in a presentation, and which of its fields to reveal.
pub struct ClaimSelection {
    pub claim_id: String,
    pub fields: FieldSelector,
}

/// Why building a presentation failed — distinct from the storage [`Result`] so a caller can
/// tell a bad *selection* from a bad *file*.
#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    /// A `FieldSelector::Only` listed no fields.
    EmptySelection,
    /// A selected field key is not part of the claim's category.
    UnknownField { claim: String, key: String },
    /// No held claim has the selected id.
    UnknownClaim(String),
    /// Deriving the disclosure failed (e.g. a malformed stored claim).
    Build(ClaimReject),
    /// No held claim can satisfy a requested predicate.
    UnsatisfiablePredicate(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::EmptySelection => f.write_str("a field selection listed no fields"),
            WalletError::UnknownField { claim, key } => {
                write!(f, "claim {claim} has no field {key}")
            }
            WalletError::UnknownClaim(id) => write!(f, "no held claim with id {id}"),
            WalletError::Build(r) => write!(f, "could not build disclosure: {r}"),
            WalletError::UnsatisfiablePredicate(label) => {
                write!(f, "no held claim satisfies predicate: {label}")
            }
        }
    }
}

impl std::error::Error for WalletError {}

/// HKDF `info` and AEAD `aad` — version-bind the wallet's encryption.
const WALLET_INFO: &[u8] = b"aion-trust-wallet/key/v1";
const WALLET_AAD: &[u8] = b"aion-trust-wallet/v1";

/// A subject's wallet: their identity plus the claims they hold.
pub struct Wallet {
    identity: Identity,
    claims: Vec<Claim>,
}

/// On-disk form: an authenticated-encrypted blob. The secret (and PII claim bodies) are
/// encrypted under a passphrase-derived key, so the file at rest never exposes the private key.
#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u8,
    kdf_salt: String,
    nonce: String,
    ciphertext: String,
}

/// The plaintext payload, sealed inside `WalletFile.ciphertext`.
#[derive(Serialize, Deserialize)]
struct WalletInner {
    secret: String,
    claims: Vec<Claim>,
}

impl Wallet {
    /// Create a wallet around a fresh identity.
    pub fn generate() -> Self {
        Self {
            identity: Identity::generate(),
            claims: Vec::new(),
        }
    }

    /// Restore a wallet's identity from a 32-byte secret (hex), with no claims yet.
    pub fn from_secret_hex(hex: &str) -> Result<Self> {
        Ok(Self {
            identity: Identity::from_secret_hex(hex)?,
            claims: Vec::new(),
        })
    }

    pub fn did(&self) -> Did {
        self.identity.did()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Add a claim to the Trust Profile.
    pub fn add(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    /// Every claim held (the full Trust Profile).
    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    /// Look a claim up by its id.
    pub fn claim(&self, claim_id: &str) -> Option<&Claim> {
        self.claims
            .iter()
            .find(|c| c.claim_id().as_str() == claim_id)
    }

    /// Build a presentation, disclosing a chosen subset of claims and — per claim — a chosen
    /// subset of fields. An empty `selections` discloses every held claim in full. The nonce is
    /// freshly generated. Fails if a selection names an unknown claim, an unknown field, or no
    /// fields.
    pub fn present(
        &self,
        audience: &Did,
        purpose: &str,
        selections: &[ClaimSelection],
        ttl_seconds: i64,
        now: Timestamp,
    ) -> std::result::Result<Presentation, WalletError> {
        let disclosed = if selections.is_empty() {
            self.disclose_all()?
        } else {
            self.disclose_selected(selections)?
        };
        let nonce = fresh_nonce();
        Ok(build_presentation(
            &self.identity,
            audience,
            purpose,
            &nonce,
            now,
            now.plus_seconds(ttl_seconds),
            disclosed,
        ))
    }

    /// Convenience for the common case: disclose the named claims (or all, if `claim_ids` is
    /// empty) in full. Equivalent to [`Self::present`] with a `FieldSelector::All` per claim.
    pub fn present_all(
        &self,
        audience: &Did,
        purpose: &str,
        claim_ids: &[String],
        ttl_seconds: i64,
        now: Timestamp,
    ) -> std::result::Result<Presentation, WalletError> {
        let selections: Vec<ClaimSelection> = claim_ids
            .iter()
            .map(|id| ClaimSelection {
                claim_id: id.clone(),
                fields: FieldSelector::All,
            })
            .collect();
        self.present(audience, purpose, &selections, ttl_seconds, now)
    }

    /// Answer a verifier's predicates with **minimal** disclosure: for each request, find a
    /// held claim of the right category whose field satisfies it, and disclose only that field.
    /// This is the path-finder — it reveals the coarse, issuer-attested attribute that settles
    /// the question (e.g. `degree_rank`), not the whole claim. Fails if no held claim qualifies.
    pub fn satisfy(
        &self,
        audience: &Did,
        purpose: &str,
        requests: &[PredicateRequest],
        ttl_seconds: i64,
        now: Timestamp,
    ) -> std::result::Result<Presentation, WalletError> {
        let mut disclosed = Vec::with_capacity(requests.len());
        for req in requests {
            let claim = self
                .find_satisfying(req)
                .ok_or_else(|| WalletError::UnsatisfiablePredicate(req.label()))?;
            let selector = FieldSelector::Only(vec![req.field.clone()]);
            disclosed.push(claim.disclose(&selector).map_err(WalletError::Build)?);
        }
        let nonce = fresh_nonce();
        Ok(build_presentation(
            &self.identity,
            audience,
            purpose,
            &nonce,
            now,
            now.plus_seconds(ttl_seconds),
            disclosed,
        ))
    }

    /// The first held claim of `req`'s category whose `field` exists and satisfies the
    /// comparison — the minimal candidate the path-finder will disclose.
    fn find_satisfying(&self, req: &PredicateRequest) -> Option<&Claim> {
        self.claims.iter().find(|c| {
            c.category() == req.category
                && c.field_value(&req.field)
                    .and_then(|v| evaluate_predicate(req.op, &v, &req.bound).ok())
                    .unwrap_or(false)
        })
    }

    /// Disclose every held claim in full.
    fn disclose_all(&self) -> std::result::Result<Vec<DisclosedClaim>, WalletError> {
        self.claims
            .iter()
            .map(|c| c.disclose(&FieldSelector::All).map_err(WalletError::Build))
            .collect()
    }

    /// Disclose exactly the claims named in `selections`, each with its chosen fields.
    fn disclose_selected(
        &self,
        selections: &[ClaimSelection],
    ) -> std::result::Result<Vec<DisclosedClaim>, WalletError> {
        let mut out = Vec::with_capacity(selections.len());
        for sel in selections {
            let claim = self
                .claim(&sel.claim_id)
                .ok_or_else(|| WalletError::UnknownClaim(sel.claim_id.clone()))?;
            validate_selector(claim, &sel.fields)?;
            out.push(claim.disclose(&sel.fields).map_err(WalletError::Build)?);
        }
        Ok(out)
    }

    /// Persist the wallet to `path`, encrypting the secret and claims under a key derived
    /// from `passphrase`. The file at rest never exposes the private key.
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        let inner = WalletInner {
            secret: self.identity.secret_hex(),
            claims: self.claims.clone(),
        };
        let plaintext = serde_json::to_vec(&inner)?;
        let salt = aion_context::crypto::generate_nonce();
        let nonce = aion_context::crypto::generate_nonce();
        let mut key = [0u8; 32];
        aion_context::crypto::derive_key(passphrase.as_bytes(), &salt, WALLET_INFO, &mut key)?;
        let ciphertext = aion_context::crypto::encrypt(&key, &nonce, &plaintext, WALLET_AAD)?;
        let file = WalletFile {
            version: 1,
            kdf_salt: to_hex(&salt),
            nonce: to_hex(&nonce),
            ciphertext: to_hex(&ciphertext),
        };
        std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Load a wallet from `path`, decrypting with `passphrase`. A wrong passphrase (or a
    /// tampered file) fails the AEAD authentication and returns an error.
    pub fn load(path: &Path, passphrase: &str) -> Result<Self> {
        let file: WalletFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let salt = from_hex(&file.kdf_salt)?;
        let nonce = decode_array::<12>(&file.nonce)?;
        let ciphertext = from_hex(&file.ciphertext)?;
        let mut key = [0u8; 32];
        aion_context::crypto::derive_key(passphrase.as_bytes(), &salt, WALLET_INFO, &mut key)?;
        let plaintext = aion_context::crypto::decrypt(&key, &nonce, &ciphertext, WALLET_AAD)?;
        let inner: WalletInner = serde_json::from_slice(&plaintext)?;
        Ok(Self {
            identity: Identity::from_secret_hex(&inner.secret)?,
            claims: inner.claims,
        })
    }
}

/// A fresh 192-bit nonce (two 96-bit CSPRNG draws), comfortably over the verifier's minimum.
fn fresh_nonce() -> Vec<u8> {
    let n1 = aion_context::crypto::generate_nonce();
    let n2 = aion_context::crypto::generate_nonce();
    n1.iter().chain(n2.iter()).copied().collect()
}

/// Reject a selector that lists no fields, or a field that is not part of the claim's category
/// — so the subject gets a precise error rather than a generic disclosure failure.
fn validate_selector(
    claim: &Claim,
    selector: &FieldSelector,
) -> std::result::Result<(), WalletError> {
    let FieldSelector::Only(keys) = selector else {
        return Ok(());
    };
    if keys.is_empty() {
        return Err(WalletError::EmptySelection);
    }
    let known = ClaimBody::field_keys_for_category(claim.category())
        .ok_or(WalletError::Build(ClaimReject::Malformed))?;
    for key in keys {
        if !known.contains(&key.as_str()) {
            return Err(WalletError::UnknownField {
                claim: claim.claim_id().as_str().to_string(),
                key: key.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_claims::{EmploymentBody, Validity};

    fn employment_claim(issuer: &Identity, subject: &Did) -> Claim {
        let body = ClaimBody::Employment(EmploymentBody {
            employer: "Acme".into(),
            title: "Engineer".into(),
            employment_type: "full_time".into(),
            start: "2021".into(),
            end: None,
            rehire_eligible: true,
        });
        Claim::issue(
            issuer,
            subject,
            Validity {
                from: Timestamp(0),
                until: None,
            },
            body,
        )
        .unwrap()
    }

    #[test]
    fn add_and_look_up_claims() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        let c = employment_claim(&issuer, &did);
        let id = c.claim_id().as_str().to_string();
        w.add(c);
        assert_eq!(w.claims().len(), 1);
        assert!(w.claim(&id).is_some());
        assert!(w.claim("nope").is_none());
    }

    #[test]
    fn present_selects_named_claims_else_all() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        let c1 = employment_claim(&issuer, &did);
        let c2 = employment_claim(&issuer, &did);
        let id1 = c1.claim_id().as_str().to_string();
        w.add(c1);
        w.add(c2);
        let verifier = Identity::generate().did();
        let all = w
            .present_all(&verifier, "app", &[], 3600, Timestamp(100))
            .unwrap();
        assert_eq!(all.claims.len(), 2); // empty selector → all
        let one = w
            .present_all(&verifier, "app", &[id1], 3600, Timestamp(100))
            .unwrap();
        assert_eq!(one.claims.len(), 1); // named selector → just that claim
    }

    #[test]
    fn present_discloses_only_selected_fields() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        let c = employment_claim(&issuer, &did);
        let id = c.claim_id().as_str().to_string();
        w.add(c);
        let verifier = Identity::generate().did();
        let sel = ClaimSelection {
            claim_id: id,
            fields: FieldSelector::Only(vec!["employer".into(), "title".into()]),
        };
        let p = w
            .present(&verifier, "app", &[sel], 3600, Timestamp(100))
            .unwrap();
        let disclosed: Vec<&str> = p.claims[0].disclosed_keys().collect();
        assert_eq!(disclosed, ["employer", "title"]);
    }

    #[test]
    fn present_rejects_bad_selections() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        let c = employment_claim(&issuer, &did);
        let id = c.claim_id().as_str().to_string();
        w.add(c);
        let verifier = Identity::generate().did();
        let empty = ClaimSelection {
            claim_id: id.clone(),
            fields: FieldSelector::Only(vec![]),
        };
        assert_eq!(
            w.present(&verifier, "app", &[empty], 3600, Timestamp(100))
                .unwrap_err(),
            WalletError::EmptySelection
        );
        let unknown_field = ClaimSelection {
            claim_id: id.clone(),
            fields: FieldSelector::Only(vec!["salary".into()]),
        };
        assert!(matches!(
            w.present(&verifier, "app", &[unknown_field], 3600, Timestamp(100))
                .unwrap_err(),
            WalletError::UnknownField { .. }
        ));
        let unknown_claim = ClaimSelection {
            claim_id: "did:aion:nope".into(),
            fields: FieldSelector::All,
        };
        assert_eq!(
            w.present(&verifier, "app", &[unknown_claim], 3600, Timestamp(100))
                .unwrap_err(),
            WalletError::UnknownClaim("did:aion:nope".into())
        );
    }

    #[test]
    fn wallet_error_messages_are_specific() {
        assert!(WalletError::EmptySelection
            .to_string()
            .contains("no fields"));
        assert!(WalletError::UnknownClaim("x".into())
            .to_string()
            .contains('x'));
        let uf = WalletError::UnknownField {
            claim: "c".into(),
            key: "salary".into(),
        };
        assert!(uf.to_string().contains("salary"));
        assert!(WalletError::UnsatisfiablePredicate("deg".into())
            .to_string()
            .contains("deg"));
    }

    #[test]
    fn satisfy_path_finds_minimal_field_or_fails() {
        use aion_trust_claims::{EducationBody, PredicateOp, PredicateRequest};
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        let body = ClaimBody::Education(EducationBody {
            institution: "State U".into(),
            credential: "M.S.".into(),
            conferred: "2020".into(),
            aion_edu_ref: None,
            degree_rank: Some(4),
        });
        w.add(
            Claim::issue(
                &issuer,
                &did,
                Validity {
                    from: Timestamp(0),
                    until: None,
                },
                body,
            )
            .unwrap(),
        );
        let audience = Identity::generate().did();
        let want = |bound| PredicateRequest {
            category: "education".into(),
            field: "degree_rank".into(),
            op: PredicateOp::Ge,
            bound: serde_json::json!(bound),
            scale_version: None,
        };
        // A satisfiable predicate discloses ONLY degree_rank.
        let p = w
            .satisfy(&audience, "app", &[want(3)], 3600, Timestamp(100))
            .unwrap();
        let disclosed: Vec<&str> = p.claims[0].disclosed_keys().collect();
        assert_eq!(disclosed, ["degree_rank"]);
        // An unsatisfiable one (require doctorate) errors rather than over-discloses.
        assert!(matches!(
            w.satisfy(&audience, "app", &[want(5)], 3600, Timestamp(100)),
            Err(WalletError::UnsatisfiablePredicate(_))
        ));
    }

    fn temp_path(did: &Did) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aion-wallet-test-{}.json",
            did.as_str().replace(':', "_")
        ))
    }

    #[test]
    fn save_then_load_round_trips_under_passphrase() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        w.add(employment_claim(&issuer, &did));
        let path = temp_path(&did);
        w.save(&path, "correct horse battery staple").unwrap();
        // the file at rest must NOT contain the plaintext secret
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(&w.identity().secret_hex()));
        let loaded = Wallet::load(&path, "correct horse battery staple").unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.did(), did); // same identity
        assert_eq!(loaded.claims().len(), 1); // same claims
    }

    #[test]
    fn wrong_passphrase_fails_to_load() {
        let mut w = Wallet::generate();
        let did = w.did();
        w.add(employment_claim(&Identity::generate(), &did));
        let path = temp_path(&did);
        w.save(&path, "right").unwrap();
        let bad = Wallet::load(&path, "wrong");
        let _ = std::fs::remove_file(&path);
        assert!(bad.is_err()); // AEAD authentication fails
    }
}
