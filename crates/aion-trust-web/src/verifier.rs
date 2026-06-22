//! Employer verifier surface: render the pending presentation and verify it offline against the
//! registry, showing the result check-by-check.
//!
//! The verdict is computed at one frozen epoch: the handler holds the state lock across the whole
//! `set_epoch → verify_presentation_with_store` section (synchronous, no `.await` while borrowing
//! the registry), honoring the Registry epoch-freeze contract.

use axum::extract::{Form, State};
use axum::response::Html;
use serde::Deserialize;

use aion_trust_claims::verify_presentation_with_store;
use aion_trust_core::Timestamp;

use crate::parse::parse_predicates;
use crate::state::{AppState, Shared};
use crate::view::{self, check_row, esc, verdict};

/// GET /verify — show the pending presentation and the Verify control.
pub(crate) async fn page(State(state): State<Shared>) -> Html<String> {
    let body = match state.lock() {
        Ok(app) => verify_body(&app, None),
        Err(_) => locked_error(),
    };
    view::page("Verify", "/verify", &body)
}

#[derive(Deserialize)]
pub(crate) struct VerifyForm {
    #[serde(default)]
    predicates: String,
}

/// POST /verify/run — verify the pending presentation, optionally requiring predicates.
pub(crate) async fn run(State(state): State<Shared>, Form(form): Form<VerifyForm>) -> Html<String> {
    let body = match state.lock() {
        Ok(mut app) => run_verify(&mut app, &form.predicates),
        Err(_) => locked_error(),
    };
    view::page("Verify", "/verify", &body)
}

/// Run the verification and render the report above the standard page body.
fn run_verify(app: &mut AppState, predicates_text: &str) -> String {
    if app.last_presentation.is_none() {
        return verify_body(
            app,
            Some(notice("Build a presentation in the wallet first.")),
        );
    }
    let preds = match parse_predicates(predicates_text) {
        Ok(p) => p,
        Err(e) => return verify_body(app, Some(error_block(&e))),
    };
    let presentation = app.last_presentation.clone();
    let Some(p) = presentation else {
        return verify_body(
            app,
            Some(notice("Build a presentation in the wallet first.")),
        );
    };
    let audience = app.employer.did();
    app.registry.set_epoch(app.epoch); // freeze the epoch for this single verdict
    let now = Timestamp::now();
    let report = match verify_presentation_with_store(
        &p,
        &audience,
        now,
        &app.registry,
        &mut app.nonces,
        &preds,
    ) {
        Ok(r) => r,
        Err(e) => return verify_body(app, Some(error_block(&format!("verification error: {e}")))),
    };
    let rows: String = report.checks.iter().map(check_row).collect();
    let result = format!(
        r#"<div class="panel"><h2>Verification report</h2>{rows}{verd}</div>"#,
        verd = verdict(report.accepted),
    );
    verify_body(app, Some(result))
}

/// The page body: an optional result block, then the pending-presentation summary + Verify form.
fn verify_body(app: &AppState, result: Option<String>) -> String {
    let head = result.unwrap_or_default();
    let Some(p) = app.last_presentation.as_ref() else {
        return format!(
            r#"{head}<p class="kicker">employer · verifier</p><h1>Verify a presentation</h1>
{}"#,
            notice(
                r#"No presentation submitted yet. Open the <a href="/wallet">candidate wallet</a> and build one."#
            ),
        );
    };
    let claims: String = p
        .claims
        .iter()
        .map(|c| {
            let keys: String = c
                .disclosed_keys()
                .map(|k| format!(r#"<span class="badge warn">{}</span> "#, esc(k)))
                .collect();
            format!(
                r#"<tr><td>{}</td><td class="mono">{}</td><td>{keys}</td></tr>"#,
                esc(c.category()),
                esc(c.claim_id().as_str()),
            )
        })
        .collect();
    format!(
        r#"{head}<p class="kicker">employer · verifier</p><h1>Verify a presentation</h1>
<div class="panel"><h2>Pending presentation</h2>
<p class="lede">Purpose <code>{purpose}</code> · audience <code>{aud}</code> · {n} claim(s)</p>
<table><thead><tr><th>category</th><th>claim id</th><th>disclosed fields</th></tr></thead><tbody>{claims}</tbody></table></div>
<form class="stack panel" method="post" action="/verify/run">
<label class="field">Required predicates (optional, one per line: <code>category:field:op:bound</code>)
<textarea name="predicates" rows="2" placeholder="education:degree_rank:ge:3"></textarea></label>
<button class="button" type="submit">Verify presentation</button></form>"#,
        purpose = esc(&p.purpose),
        aud = esc(p.audience.as_str()),
        n = p.claims.len(),
    )
}

fn notice(msg: &str) -> String {
    format!(r#"<div class="notice">{msg}</div>"#)
}

fn error_block(msg: &str) -> String {
    format!(
        r#"<div class="panel"><div class="verdict rejected">REJECTED</div><p class="lede">{}</p></div>"#,
        esc(msg)
    )
}

fn locked_error() -> String {
    notice("The demo state is busy — please retry.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn app() -> AppState {
        AppState::seed()
    }

    #[test]
    fn empty_state_prompts_to_build_a_presentation() {
        let body = verify_body(&app(), None);
        assert!(body.contains("No presentation submitted yet"));
        assert!(body.contains(r#"href="/wallet""#));
    }

    #[test]
    fn run_without_presentation_is_a_notice_not_a_panic() {
        let mut a = app();
        let body = run_verify(&mut a, "");
        assert!(body.contains("Build a presentation in the wallet first"));
    }

    #[test]
    fn malformed_predicate_is_reported_not_verified() {
        let mut a = app();
        // give it a presentation so it gets past the empty check
        a.last_presentation = Some(
            a.wallet
                .present_all(&a.employer.did(), "app", &[], 3600, Timestamp(100))
                .unwrap(),
        );
        let body = run_verify(&mut a, "bad-line");
        assert!(body.contains("predicate needs"));
    }

    #[tokio::test]
    async fn page_renders_through_shared_state() {
        let s: Shared = Arc::new(Mutex::new(app()));
        let html = page(State(s)).await.0;
        assert!(html.contains("Verify a presentation"));
    }

    /// The headline demo, asserted as a state machine: a presentation that verifies green flips
    /// to red the instant its claim is revoked.
    #[test]
    fn accepted_then_revoke_flips_to_rejected() {
        let mut a = app();
        let id = a.wallet.claims()[0].claim_id().as_str().to_string();
        let present = |a: &mut AppState| {
            a.last_presentation = Some(
                a.wallet
                    .present_all(
                        &a.employer.did(),
                        "app",
                        std::slice::from_ref(&id),
                        3600,
                        Timestamp::now(),
                    )
                    .unwrap(),
            );
        };
        present(&mut a);
        let green = run_verify(&mut a, "");
        assert!(green.contains("ACCEPTED"), "expected green: {green}");

        let epoch = a.epoch;
        a.registry.revoke(&id, epoch); // the issuer withdraws the claim
        present(&mut a); // re-present (fresh nonce, so the failure is revocation, not replay)
        let red = run_verify(&mut a, "");
        assert!(red.contains("REJECTED"), "expected red after revoke");
        assert!(red.contains("claim not revoked")); // the specific failing check
    }

    #[test]
    fn replaying_the_same_presentation_is_rejected() {
        let mut a = app();
        let id = a.wallet.claims()[0].claim_id().as_str().to_string();
        a.last_presentation = Some(
            a.wallet
                .present_all(&a.employer.did(), "app", &[id], 3600, Timestamp::now())
                .unwrap(),
        );
        assert!(run_verify(&mut a, "").contains("ACCEPTED")); // first use records the nonce
        let again = run_verify(&mut a, ""); // same presentation, not rebuilt → replay
        assert!(again.contains("REJECTED"));
        assert!(again.contains("nonce fresh"));
    }
}
