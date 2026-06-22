//! aion-trust-web — the three demo surfaces (issuer console · candidate wallet · employer
//! verifier) plus a live walkthrough, served as one local axum app.
//!
//! **LOCAL SINGLE-OPERATOR DEMO — NOT A HOSTED SERVICE, NOT A CUSTODY ARCHITECTURE.** This one
//! process holds the operator's *own* issuer, accreditor, and candidate secret keys in memory
//! for the session, binds to loopback only, and discards everything on exit. That co-location
//! of three trust domains in one binary is a demo convenience — it is the one thing **not** to
//! copy. In production the wallet runs on the subject's device, the issuer runs its own signing
//! service, and the verifier holds only public keys + the registry; the three surfaces are three
//! different parties on three different machines. The aion-context registry holds no PII in any
//! deployment. See `docs/WEB-SURFACES.md`.

#![forbid(unsafe_code)]

mod issuer;
mod parse;
mod state;
mod verifier;
mod view;
mod walkthrough;
mod wallet;

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Router;

use state::{AppState, Shared};

/// Loopback only. This demo must never be reachable off the operator's own machine — binding
/// elsewhere would invite the very server-side, multi-subject custody model aion-trust exists to
/// refute (invariant #2: the subject owns the artifact; no central store of subjects).
const LOOPBACK: &str = "127.0.0.1";

/// Run the demo on `127.0.0.1:port`, building its own tokio runtime. Blocks until shutdown.
///
/// # Errors
/// Propagates I/O errors from binding the listener or serving.
pub fn serve(port: u16) -> std::io::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind((LOOPBACK, port)).await?;
        println!(
            "aion-trust web demo → http://{LOOPBACK}:{port}  (local single-operator; Ctrl-C to stop)"
        );
        axum::serve(listener, router()).await
    })
}

/// Build the router over a freshly seeded in-memory world.
fn router() -> Router {
    let state: Shared = Arc::new(Mutex::new(AppState::seed()));
    Router::new()
        .route("/", get(home))
        .route("/app.css", get(app_css))
        .route("/favicon.svg", get(favicon))
        .route("/api/reset", post(reset))
        .route("/issuer", get(issuer::page))
        .route("/issuer/issue", post(issuer::issue))
        .route("/issuer/revoke", post(issuer::revoke))
        .route("/issuer/advance-epoch", post(issuer::advance_epoch))
        .route("/wallet", get(wallet::page))
        .route("/wallet/present", post(wallet::present))
        .route("/wallet/disclose", post(wallet::disclose))
        .route("/wallet/satisfy", post(wallet::satisfy))
        .route("/verify", get(verifier::page))
        .route("/verify/run", post(verifier::run))
        .route("/walkthrough", get(walkthrough::page))
        .route("/walkthrough/stream", get(walkthrough::stream))
        .with_state(state)
}

async fn home() -> Html<String> {
    let body = r#"
<section class="hero">
<p class="kicker">The verifiable résumé</p>
<h1>A résumé you can prove.</h1>
<p class="lede">Each fact about a person is attested once, at its source, and signed — then
verified by anyone, offline, with no phone calls and no callbacks. Verification done once becomes
an artifact reused across every application. Below are the three parties, each its own room.</p>
</section>
<div class="rooms">
  <a class="room" href="/issuer"><span class="role">Issuer</span><h2>Issuer console</h2>
    <p>Attest a fact and hand the signed claim to the candidate. Accredit issuers; revoke a claim.</p>
    <span class="go">/issuer →</span></a>
  <a class="room" href="/wallet"><span class="role">Candidate</span><h2>Candidate wallet</h2>
    <p>Hold your claims; build a minimized, audience-bound presentation — full claims, chosen fields, or predicate proofs.</p>
    <span class="go">/wallet →</span></a>
  <a class="room" href="/verify"><span class="role">Employer</span><h2>Employer verifier</h2>
    <p>Check a presentation offline against the registry — binding, authenticity, accreditation, revocation, one check at a time.</p>
    <span class="go">/verify →</span></a>
  <a class="room feature" href="/walkthrough"><span class="role">Watch it happen</span><h2>Live walkthrough</h2>
    <p>Issue → present → verify (green) → the issuer revokes → the same presentation now fails (red), streamed live.</p>
    <span class="go">/walkthrough →</span></a>
</div>
<div class="notice"><span class="badge ok">scope</span> <span><strong>Local single-operator demo.</strong> This process holds the
operator's own keys in memory and binds to loopback only — it is not a hosted service and not a
custody architecture. State resets on restart, or with the button below.</span></div>
<form class="stack" method="post" action="/api/reset"><button class="button ghost" type="submit">Reset demo state</button></form>
"#;
    view::page("Home", "/", body)
}

async fn app_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/app.css"),
    )
}

async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml")],
        include_str!("../web/logo.svg"),
    )
}

/// Re-seed the world (the demo's reset control), then redirect home.
async fn reset(State(state): State<Shared>) -> Redirect {
    if let Ok(mut app) = state.lock() {
        app.reset();
    }
    Redirect::to("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_core::Timestamp;

    fn shared() -> Shared {
        Arc::new(Mutex::new(AppState::seed()))
    }

    #[tokio::test]
    async fn home_lists_the_surfaces() {
        let html = home().await.0;
        for path in ["/issuer", "/wallet", "/verify", "/walkthrough"] {
            assert!(html.contains(path), "home missing link to {path}");
        }
        assert!(html.contains("Local single-operator demo"));
    }

    #[tokio::test]
    async fn reset_reseeds_state() {
        let s = shared();
        s.lock().unwrap().epoch = 42;
        let _ = reset(State(s.clone())).await;
        assert_eq!(s.lock().unwrap().epoch, 1);
    }

    #[test]
    fn loopback_is_hardcoded() {
        assert_eq!(LOOPBACK, "127.0.0.1"); // never 0.0.0.0
    }

    /// No surface may ever render a private key. Seed a world, collect every secret, render all
    /// surfaces, and assert none of the secrets appears in the HTML.
    #[tokio::test]
    async fn no_surface_leaks_a_secret_key() {
        let app = AppState::seed();
        let mut secrets = vec![
            app.employer.secret_hex(),
            app.wallet.identity().secret_hex(),
        ];
        for slot in app.issuers.values() {
            secrets.push(slot.identity.secret_hex());
        }
        // Build a real presentation so the with-presentation render paths (verifier/wallet,
        // which handle disclosed bodies) are exercised, not just the empty pages.
        let s: Shared = {
            let mut a = app;
            let aud = a.employer.did();
            a.last_presentation = Some(
                a.wallet
                    .present_all(&aud, "app", &[], 3600, Timestamp::now())
                    .unwrap(),
            );
            Arc::new(Mutex::new(a))
        };
        let pages = [
            home().await.0,
            issuer::page(State(s.clone())).await.0,
            wallet::page(State(s.clone())).await.0,
            verifier::page(State(s.clone())).await.0,
        ];
        for html in &pages {
            for secret in &secrets {
                assert!(
                    !html.contains(secret.as_str()),
                    "a surface leaked a private key"
                );
            }
        }
    }
}
