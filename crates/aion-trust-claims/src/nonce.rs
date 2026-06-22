//! Single-use nonce enforcement — the verifier's anti-replay memory.
//!
//! A presentation is bound (by the subject's signature) to one audience, one nonce, and an
//! expiry. That stops a *stolen* presentation from being replayed against a different audience
//! (the signature won't match) or after it expires. It does **not**, by itself, stop the same
//! presentation being replayed to the *same* audience before it expires — for that the verifier
//! must remember the nonces it has accepted. [`NonceStore`] is that memory; the verifier owns
//! it and updates it itself, rather than trusting a caller-supplied "already seen" flag.
//!
//! **Atomicity & concurrency (read this before deploying).** [`verify_presentation_with_store`]
//! reads the store, runs verification, and — only if the presentation is accepted — records the
//! nonce. In a single-process, single-threaded verifier this is atomic and correct. A
//! multi-process or multi-threaded verifier that does **not** share one synchronized store has
//! **no cross-replica replay protection**: the same presentation replayed to two replicas can
//! be accepted twice. A shared store must make check-and-record a single atomic operation.
//! Replay/expiry safety also assumes an honest, monotonic `now` supplied at the verifier.

use std::collections::HashMap;

use aion_trust_core::{Did, Result, Timestamp};

use crate::anchor::TrustAnchor;
use crate::predicate::PredicateRequest;
use crate::presentation::{verify_presentation_with_predicates, Presentation, VerificationReport};

/// A verifier's record of the presentations it has already accepted, for single-use
/// enforcement. Keyed by `(audience, nonce)`: a nonce is the verifier's freshness challenge, so
/// uniqueness need only hold within the audience that would reject the replay — and that is
/// sound precisely because `audience` is inside the subject's signature.
pub trait NonceStore {
    /// Whether `(audience, nonce)` was already consumed by an accepted presentation.
    fn seen(&self, audience: &Did, nonce: &str) -> bool;
    /// Record `(audience, nonce)` as consumed, remembering the presentation's `expires_at` so
    /// the entry can later be safely evicted. Call **only** for an accepted presentation.
    fn record(&mut self, audience: &Did, nonce: &str, expires_at: Timestamp);
}

/// The reference in-memory store. Suitable for a single-process verifier; see the module note
/// on concurrency before sharing one across replicas.
#[derive(Default)]
pub struct InMemoryNonceStore {
    /// `(audience, nonce) -> expires_at` of the presentation that consumed it.
    seen: HashMap<(Did, String), Timestamp>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many nonces are currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Drop every nonce whose presentation has expired (`now > expires_at`). Safe — an expired
    /// presentation is already rejected by the unexpired check, so forgetting its nonce cannot
    /// reopen a replay window. Eviction is strictly `>`: a nonce is kept at `now == expires_at`
    /// (the boundary the unexpired check still accepts).
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.seen.retain(|_, &mut expires_at| now <= expires_at);
    }
}

impl NonceStore for InMemoryNonceStore {
    fn seen(&self, audience: &Did, nonce: &str) -> bool {
        self.seen
            .contains_key(&(audience.clone(), nonce.to_string()))
    }

    fn record(&mut self, audience: &Did, nonce: &str, expires_at: Timestamp) {
        self.seen
            .insert((audience.clone(), nonce.to_string()), expires_at);
    }
}

/// Verify a presentation and enforce single-use against `store`, optionally requiring
/// `predicates`. Reads the store for the freshness check, verifies, and records the nonce
/// **only if the presentation is accepted** — so a presentation that fails any check does not
/// burn its nonce (no replay-poisoning DoS). This is the entry point a real verifier should
/// call: it combines replay protection with predicate checks so neither has to be hand-managed.
/// Pass `&[]` for `predicates` when none are required.
pub fn verify_presentation_with_store(
    p: &Presentation,
    audience: &Did,
    now: Timestamp,
    anchor: &impl TrustAnchor,
    store: &mut impl NonceStore,
    predicates: &[PredicateRequest],
) -> Result<VerificationReport> {
    let already_seen = store.seen(audience, &p.nonce);
    let report =
        verify_presentation_with_predicates(p, audience, now, anchor, already_seen, predicates)?;
    if report.accepted {
        store.record(audience, &p.nonce, p.expires_at);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::from_string(s.into())
    }

    #[test]
    fn records_and_reports_seen_by_audience_and_nonce() {
        let mut store = InMemoryNonceStore::new();
        let a = did("did:aion:a");
        let b = did("did:aion:b");
        assert!(!store.seen(&a, "n1"));
        assert!(store.is_empty()); // empty before any record
        store.record(&a, "n1", Timestamp(100));
        assert!(store.seen(&a, "n1")); // same pair → seen
        assert!(!store.seen(&b, "n1")); // same nonce, different audience → not seen
        assert!(!store.seen(&a, "n2")); // different nonce → not seen
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty()); // not empty after a record — pins is_empty
    }

    #[test]
    fn eviction_is_strictly_greater_than_expiry() {
        let mut store = InMemoryNonceStore::new();
        let a = did("did:aion:a");
        store.record(&a, "n1", Timestamp(100));
        store.evict_expired(Timestamp(100)); // now == expires_at → kept
        assert!(store.seen(&a, "n1"));
        store.evict_expired(Timestamp(101)); // now > expires_at → evicted
        assert!(!store.seen(&a, "n1"));
        assert!(store.is_empty());
    }
}
