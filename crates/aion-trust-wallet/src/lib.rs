//! aion-trust-wallet — the subject's side of the system.
//!
//! A [`Wallet`] holds the subject's cryptographic [`Identity`] and their **Trust Profile**:
//! every claim they have been issued. From it the subject builds a minimized, audience-bound
//! [`Presentation`] — the artifact that replaces the résumé. The wallet is the only place the
//! PII-bearing claim bodies live; nothing here ever touches a shared ledger.

use std::path::Path;

use aion_trust_claims::{build_presentation, Claim, Presentation};
use aion_trust_core::{Did, Identity, Result, Timestamp};
use serde::{Deserialize, Serialize};

/// A subject's wallet: their identity plus the claims they hold.
pub struct Wallet {
    identity: Identity,
    claims: Vec<Claim>,
}

/// On-disk form. Holds the secret — write only to a protected, gitignored location.
#[derive(Serialize, Deserialize)]
struct WalletFile {
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

    /// Build a presentation for one verifier. If `claim_ids` is empty, every held claim is
    /// disclosed; otherwise only the named claims. The nonce is freshly generated.
    pub fn present(
        &self,
        audience: &Did,
        purpose: &str,
        claim_ids: &[String],
        ttl_seconds: i64,
        now: Timestamp,
    ) -> Presentation {
        let selected: Vec<Claim> = if claim_ids.is_empty() {
            self.claims.clone()
        } else {
            self.claims
                .iter()
                .filter(|c| claim_ids.iter().any(|id| id == c.claim_id().as_str()))
                .cloned()
                .collect()
        };
        let n1 = aion_context::crypto::generate_nonce();
        let n2 = aion_context::crypto::generate_nonce();
        let nonce: Vec<u8> = n1.iter().chain(n2.iter()).copied().collect();
        build_presentation(
            &self.identity,
            audience,
            purpose,
            &nonce,
            now,
            now.plus_seconds(ttl_seconds),
            selected,
        )
    }

    /// Persist the wallet (including the secret) to `path` as JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = WalletFile {
            secret: self.identity.secret_hex(),
            claims: self.claims.clone(),
        };
        std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Load a wallet (identity + claims) from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let file: WalletFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Ok(Self {
            identity: Identity::from_secret_hex(&file.secret)?,
            claims: file.claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_claims::{ClaimBody, EmploymentBody, Validity};

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
        let all = w.present(&verifier, "app", &[], 3600, Timestamp(100));
        assert_eq!(all.claims.len(), 2); // empty selector → all
        let one = w.present(&verifier, "app", &[id1], 3600, Timestamp(100));
        assert_eq!(one.claims.len(), 1); // named selector → just that claim
    }

    #[test]
    fn save_then_load_preserves_identity_and_claims() {
        let issuer = Identity::generate();
        let mut w = Wallet::generate();
        let did = w.did();
        w.add(employment_claim(&issuer, &did));
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "aion-wallet-test-{}.json",
            did.as_str().replace(':', "_")
        ));
        w.save(&path).unwrap();
        let loaded = Wallet::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.did(), did); // same identity
        assert_eq!(loaded.claims().len(), 1); // same claims
    }
}
