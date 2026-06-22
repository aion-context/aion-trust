//! Candidate wallet surface: hold claims and build a minimized, audience-bound presentation —
//! full claims, a chosen subset of fields, or a predicate proof (minimal disclosure). The built
//! presentation is stashed in [`AppState::last_presentation`] for the verifier surface to check.
//!
//! Rendering the operator's own claim *fields* here is the operator viewing their own PII on
//! their own loopback browser — sovereignty, not leakage. Every value is HTML-escaped, and only
//! a presentation the operator explicitly builds is ever handed to the verifier.

use axum::extract::State;
use axum::response::Html;

use aion_trust_claims::{ClaimBody, FieldSelector};
use aion_trust_core::Timestamp;
use aion_trust_wallet::ClaimSelection;

use crate::parse::{first, form_pairs, parse_predicates, values};
use crate::state::{AppState, Shared};
use crate::view::{self, esc};

const DEFAULT_TTL: i64 = 604_800; // one week

/// GET /wallet.
pub(crate) async fn page(State(state): State<Shared>) -> Html<String> {
    let body = match state.lock() {
        Ok(app) => wallet_body(&app, None),
        Err(_) => busy(),
    };
    view::page("Wallet", "/wallet", &body)
}

/// POST /wallet/present — disclose the checked claims in FULL.
pub(crate) async fn present(State(state): State<Shared>, body: String) -> Html<String> {
    let pairs = form_pairs(&body);
    let claim_ids: Vec<String> = values(&pairs, "claim")
        .iter()
        .map(|s| s.to_string())
        .collect();
    let purpose = first(&pairs, "purpose")
        .unwrap_or("application")
        .to_string();
    let ttl = first(&pairs, "ttl")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL);
    let rendered = match state.lock() {
        Ok(mut app) => {
            let audience = app.employer.did();
            let built =
                app.wallet
                    .present_all(&audience, &purpose, &claim_ids, ttl, Timestamp::now());
            store_or_warn(&mut app, built.map_err(|e| e.to_string()))
        }
        Err(_) => busy(),
    };
    view::page("Wallet", "/wallet", &rendered)
}

/// POST /wallet/disclose — disclose ONLY the checked fields of a single claim.
pub(crate) async fn disclose(State(state): State<Shared>, body: String) -> Html<String> {
    let pairs = form_pairs(&body);
    let Some(claim_id) = first(&pairs, "claim").map(str::to_string) else {
        return view::page("Wallet", "/wallet", &warn("no claim selected"));
    };
    let fields: Vec<String> = values(&pairs, "field")
        .iter()
        .map(|s| s.to_string())
        .collect();
    let selector = if fields.is_empty() {
        FieldSelector::All
    } else {
        FieldSelector::Only(fields)
    };
    let purpose = first(&pairs, "purpose")
        .unwrap_or("application")
        .to_string();
    let rendered = match state.lock() {
        Ok(mut app) => {
            let audience = app.employer.did();
            let selection = [ClaimSelection {
                claim_id,
                fields: selector,
            }];
            let built = app.wallet.present(
                &audience,
                &purpose,
                &selection,
                DEFAULT_TTL,
                Timestamp::now(),
            );
            store_or_warn(&mut app, built.map_err(|e| e.to_string()))
        }
        Err(_) => busy(),
    };
    view::page("Wallet", "/wallet", &rendered)
}

/// POST /wallet/satisfy — answer predicate requests with minimal disclosure (path-finding).
pub(crate) async fn satisfy(State(state): State<Shared>, body: String) -> Html<String> {
    let pairs = form_pairs(&body);
    let text = first(&pairs, "predicates").unwrap_or("");
    let purpose = first(&pairs, "purpose")
        .unwrap_or("application")
        .to_string();
    let rendered = match parse_predicates(text) {
        Err(e) => render_locked(&state, |app| wallet_body(app, Some(warn(&e)))),
        Ok(reqs) => match state.lock() {
            Ok(mut app) => {
                let audience = app.employer.did();
                let built =
                    app.wallet
                        .satisfy(&audience, &purpose, &reqs, DEFAULT_TTL, Timestamp::now());
                store_or_warn(&mut app, built.map_err(|e| e.to_string()))
            }
            Err(_) => busy(),
        },
    };
    view::page("Wallet", "/wallet", &rendered)
}

/// Store a freshly built presentation (or render its error), then re-render the page.
fn store_or_warn(
    app: &mut AppState,
    built: Result<aion_trust_claims::Presentation, String>,
) -> String {
    match built {
        Ok(p) => {
            let n = p.claims.len();
            app.last_presentation = Some(p);
            wallet_body(
                app,
                Some(ok(&format!(
                    r#"Presentation built ({n} claim(s)). Go to the <a href="/verify">verifier</a>."#
                ))),
            )
        }
        Err(e) => wallet_body(app, Some(warn(&e))),
    }
}

fn render_locked(state: &Shared, f: impl FnOnce(&AppState) -> String) -> String {
    match state.lock() {
        Ok(app) => f(&app),
        Err(_) => busy(),
    }
}

/// The wallet page: the pending presentation (if any), the full-presentation builder, a
/// per-claim selective-disclosure form, and the predicate-proof form.
fn wallet_body(app: &AppState, flash: Option<String>) -> String {
    let head = flash.unwrap_or_default();
    let pending = match &app.last_presentation {
        Some(p) => format!(
            r#"<div class="notice">Pending presentation: {n} claim(s) for <code>{aud}</code>. <a href="/verify">Verify →</a></div>"#,
            n = p.claims.len(),
            aud = esc(p.audience.as_str()),
        ),
        None => String::new(),
    };
    let cards: String = app
        .wallet
        .claims()
        .iter()
        .map(|c| claim_block(app, c))
        .collect();
    let checklist: String = app
        .wallet
        .claims()
        .iter()
        .map(|c| {
            let id = c.claim_id().as_str();
            let label = app.claim_labels.get(id).cloned().unwrap_or_default();
            format!(
                r#"<label class="checks-inline"><input type="checkbox" name="claim" value="{}" checked> {} <span class="mono">{}</span></label>"#,
                esc(id),
                esc(&label),
                esc(c.category()),
            )
        })
        .collect();
    format!(
        r#"{head}{pending}<p class="kicker">candidate · wallet</p><h1>Your claims</h1>
<p class="lede">Build a presentation for the employer: full claims, a chosen subset of fields, or a predicate proof that reveals only the minimum.</p>
<form class="stack panel" method="post" action="/wallet/present"><h2>Present full claims</h2>
{checklist}
<label class="field">Purpose<input type="text" name="purpose" value="application:senior-engineer"></label>
<button class="button" type="submit">Build full presentation →</button></form>
<div class="panel"><h2>Predicate proof (minimal disclosure)</h2>
<form class="stack" method="post" action="/wallet/satisfy">
<label class="field">Predicates (one per line: <code>category:field:op:bound</code>)
<textarea name="predicates" rows="2">education:degree_rank:ge:3</textarea></label>
<button class="button amber" type="submit">Prove predicates →</button></form>
<p class="lede">Reveals only the coarse, issuer-attested attribute that answers the question — data minimization, not zero-knowledge.</p></div>
<h2>Per-claim selective disclosure</h2>
<div class="grid">{cards}</div>"#,
    )
}

/// One claim as a card with a field-level disclosure form.
fn claim_block(app: &AppState, c: &aion_trust_claims::Claim) -> String {
    let id = c.claim_id().as_str();
    let label = app.claim_labels.get(id).cloned().unwrap_or_default();
    let keys = ClaimBody::field_keys_for_category(c.category()).unwrap_or(&[]);
    let boxes: String = keys
        .iter()
        .map(|k| {
            format!(
                r#"<label class="checks-inline"><input type="checkbox" name="field" value="{k}"> {k}</label>"#,
                k = esc(k),
            )
        })
        .collect();
    format!(
        r#"<form class="stack panel" method="post" action="/wallet/disclose">
<h3>{label}</h3><p class="mono">{cat} · {id}</p>
<input type="hidden" name="claim" value="{id_attr}">
{boxes}
<button class="button ghost" type="submit">Present selected fields →</button></form>"#,
        label = esc(&label),
        cat = esc(c.category()),
        id = esc(id),
        id_attr = esc(id),
    )
}

/// NOTE: `msg` is treated as **trusted HTML** (callers embed the `/verify` link). Never pass
/// unescaped user input — use [`warn`] (which escapes) for that.
fn ok(msg: &str) -> String {
    format!(r#"<div class="notice"><span class="badge ok">ok</span> {msg}</div>"#)
}
fn warn(msg: &str) -> String {
    format!(
        r#"<div class="notice"><span class="badge bad">error</span> {}</div>"#,
        esc(msg)
    )
}
fn busy() -> String {
    r#"<div class="notice">The demo state is busy — please retry.</div>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn full_present_stores_a_presentation() {
        let mut app = AppState::seed();
        let ids: Vec<String> = app
            .wallet
            .claims()
            .iter()
            .map(|c| c.claim_id().as_str().to_string())
            .collect();
        let audience = app.employer.did();
        let built = app
            .wallet
            .present_all(&audience, "app", &ids, DEFAULT_TTL, Timestamp(100))
            .map_err(|e| e.to_string());
        let html = store_or_warn(&mut app, built);
        assert!(app.last_presentation.is_some());
        assert!(html.contains("Presentation built"));
    }

    #[tokio::test]
    async fn disclose_reveals_only_selected_fields() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let claim_id = s.lock().unwrap().wallet.claims()[0]
            .claim_id()
            .as_str()
            .to_string();
        let body = format!("claim={claim_id}&field=employer&field=title&purpose=app");
        let _ = disclose(State(s.clone()), body).await;
        let app = s.lock().unwrap();
        let p = app.last_presentation.as_ref().expect("presentation built");
        let keys: Vec<&str> = p.claims[0].disclosed_keys().collect();
        assert_eq!(keys, ["employer", "title"]);
    }

    #[tokio::test]
    async fn satisfy_builds_minimal_predicate_presentation() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let body = "predicates=education:degree_rank:ge:3&purpose=app".to_string();
        let _ = satisfy(State(s.clone()), body).await;
        let app = s.lock().unwrap();
        let p = app
            .last_presentation
            .as_ref()
            .expect("predicate presentation");
        // minimal disclosure: only the degree_rank field is on the wire
        let keys: Vec<&str> = p.claims[0].disclosed_keys().collect();
        assert_eq!(keys, ["degree_rank"]);
    }

    #[test]
    fn page_body_lists_claims_and_forms() {
        let app = AppState::seed();
        let body = wallet_body(&app, None);
        assert!(body.contains("Present full claims"));
        assert!(body.contains("Predicate proof"));
        assert!(body.contains("Per-claim selective disclosure"));
    }

    #[tokio::test]
    async fn disclose_without_a_claim_warns_and_stores_nothing() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let html = disclose(State(s.clone()), "field=employer".to_string())
            .await
            .0;
        assert!(html.contains("no claim selected"));
        assert!(s.lock().unwrap().last_presentation.is_none());
    }

    #[tokio::test]
    async fn disclose_with_no_fields_checked_discloses_all() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let id = s.lock().unwrap().wallet.claims()[0]
            .claim_id()
            .as_str()
            .to_string();
        let _ = disclose(State(s.clone()), format!("claim={id}")).await;
        let app = s.lock().unwrap();
        let p = app.last_presentation.as_ref().expect("built");
        // empty field selection ⇒ FieldSelector::All ⇒ every employment field disclosed
        assert_eq!(p.claims[0].disclosed_keys().count(), 6);
    }

    #[tokio::test]
    async fn present_unknown_claim_is_an_error_not_a_panic() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let html = present(
            State(s.clone()),
            "claim=did:aion:nope&purpose=app".to_string(),
        )
        .await
        .0;
        assert!(html.contains("error"));
        assert!(s.lock().unwrap().last_presentation.is_none());
    }
}
