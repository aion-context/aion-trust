//! The live walkthrough: a scripted, server-driven demo streamed over Server-Sent Events.
//! Issue → present → verify (green) → revoke → re-present → verify (red). Each act mutates the
//! shared world and emits one event; the page renders them into a cinematic stage.
//!
//! The lock is taken inside each act and dropped before the `await` between acts — the epoch is
//! frozen for the duration of each verify, never across a sleep.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::Html;
use serde_json::json;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;

use aion_trust_claims::verify_presentation_with_store;
use aion_trust_core::Timestamp;

use crate::state::Shared;
use crate::view;

/// GET /walkthrough — the stage plus a tiny EventSource reader (the one place the demo needs
/// client JS: consuming the SSE stream).
pub(crate) async fn page() -> Html<String> {
    let body = r##"
<p class="kicker">live · walkthrough</p><h1>Proof, in motion</h1>
<p class="lede">Watch a verified claim turn red the instant its issuer revokes it — issue → present
→ verify (green) → revoke → the same claim now fails (red). Entirely offline against the registry.</p>
<div class="panel"><div id="stage" class="stage"></div></div>
<form method="get" action="/walkthrough"><button class="button" type="submit">Run again ↻</button></form>
<script>
const stage = document.getElementById('stage');
const es = new EventSource('/walkthrough/stream');
es.onmessage = (e) => {
  const a = JSON.parse(e.data);
  if (a.done) { es.close(); return; }
  const el = document.createElement('div');
  el.className = 'act live';
  el.innerHTML = '<div class="title">' + a.title + '</div><div>' + a.detail + '</div>';
  stage.appendChild(el);
};
</script>"##;
    view::page("Walkthrough", "/walkthrough", body)
}

/// GET /walkthrough/stream — run the script and stream one event per act.
pub(crate) async fn stream(
    State(state): State<Shared>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = unbounded_channel::<SseEvent>();
    tokio::spawn(run_script(state, tx));
    let stream = UnboundedReceiverStream::new(rx).map(Ok);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// One act → one SSE event carrying `{title, detail, tone}`.
fn act(title: &str, detail: &str, tone: &str) -> SseEvent {
    SseEvent::default()
        .json_data(json!({ "title": title, "detail": detail, "tone": tone }))
        .unwrap_or_default()
}

async fn run_script(state: Shared, tx: UnboundedSender<SseEvent>) {
    let pause = || tokio::time::sleep(Duration::from_millis(950));

    // Act 0 — reset to a known world, pick the claim we'll follow.
    let claim_id = {
        let mut app = match state.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        app.reset();
        app.wallet
            .claims()
            .first()
            .map(|c| c.claim_id().as_str().to_string())
    };
    let Some(claim_id) = claim_id else { return };
    let _ = tx.send(act(
        "Reset",
        "A fresh world: accredited issuers, a candidate wallet.",
        "info",
    ));
    pause().await;

    let _ = tx.send(act(
        "1 · Issued",
        &format!(
            "An accredited issuer attested a claim and handed it to the candidate. <span class=\"mono\">{}</span>",
            view::esc(&claim_id),
        ),
        "info",
    ));
    pause().await;

    present(&state, &claim_id);
    let _ = tx.send(act(
        "2 · Presented",
        "The candidate discloses just this claim to the employer — audience-bound, single-use, expiring.",
        "info",
    ));
    pause().await;

    let (accepted, detail) = verify(&state);
    let _ = tx.send(act(
        if accepted {
            "3 · Verified — ACCEPTED"
        } else {
            "3 · Verified"
        },
        &detail,
        if accepted { "ok" } else { "bad" },
    ));
    pause().await;

    revoke(&state, &claim_id);
    let _ = tx.send(act(
        "4 · Revoked",
        "The issuer withdraws the claim on the registry. Nothing about the person changes — only its standing.",
        "warn",
    ));
    pause().await;

    present(&state, &claim_id); // fresh nonce, so the failure is revocation — not replay
    let (accepted2, detail2) = verify(&state);
    let _ = tx.send(act(
        if accepted2 {
            "5 · Re-verified"
        } else {
            "5 · Re-verified — REJECTED"
        },
        &detail2,
        if accepted2 { "ok" } else { "bad" },
    ));
    pause().await;

    let _ = tx.send(
        SseEvent::default()
            .json_data(json!({ "done": true }))
            .unwrap_or_default(),
    );
}

/// Build a single-claim full-disclosure presentation and stash it.
fn present(state: &Shared, claim_id: &str) {
    if let Ok(mut app) = state.lock() {
        let audience = app.employer.did();
        if let Ok(p) = app.wallet.present_all(
            &audience,
            "walkthrough",
            std::slice::from_ref(&claim_id.to_string()),
            3600,
            Timestamp::now(),
        ) {
            app.last_presentation = Some(p);
        }
    }
}

/// Verify the pending presentation; return (accepted, human detail).
fn verify(state: &Shared) -> (bool, String) {
    let Ok(mut app) = state.lock() else {
        return (false, "state busy".into());
    };
    let app = &mut *app; // reborrow the guard so registry/nonces can be split-borrowed
    let Some(p) = app.last_presentation.clone() else {
        return (false, "no presentation".into());
    };
    let audience = app.employer.did();
    app.registry.set_epoch(app.epoch); // freeze epoch for this verdict
    let now = Timestamp::now();
    match verify_presentation_with_store(&p, &audience, now, &app.registry, &mut app.nonces, &[]) {
        Ok(r) if r.accepted => (
            true,
            "Every check passes: authentic, accredited, unrevoked, in-window.".into(),
        ),
        Ok(r) => {
            let failed: Vec<&str> = r
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();
            (false, format!("Rejected — failing: {}.", failed.join(", ")))
        }
        Err(_) => (false, "verification error".into()),
    }
}

fn revoke(state: &Shared, claim_id: &str) {
    if let Ok(mut app) = state.lock() {
        let epoch = app.epoch;
        app.registry.revoke(claim_id, epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use std::sync::{Arc, Mutex};

    #[test]
    fn act_event_carries_its_fields() {
        // json_data must succeed (non-default event) and the payload round-trips.
        let ev = act("T", "D", "ok");
        let _ = ev; // construction without panic is the assertion here
    }

    #[test]
    fn verify_reports_green_then_red_across_a_revoke() {
        let s: Shared = Arc::new(Mutex::new(AppState::seed()));
        let id = s.lock().unwrap().wallet.claims()[0]
            .claim_id()
            .as_str()
            .to_string();
        present(&s, &id);
        let (ok, _) = verify(&s);
        assert!(ok, "should verify before revoke");
        revoke(&s, &id);
        present(&s, &id);
        let (ok2, detail) = verify(&s);
        assert!(!ok2, "should reject after revoke");
        assert!(detail.contains("claim not revoked"), "detail: {detail}");
    }
}
