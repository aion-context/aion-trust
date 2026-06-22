//! Issuer console: attest a fact (issue a claim into the candidate's wallet), revoke a claim,
//! and advance the registry epoch. The operator's issuer secrets stay in [`AppState`]; only
//! `did:` strings and accreditation *standing* are ever rendered.

use axum::extract::{Form, State};
use axum::response::{Html, Redirect};
use serde::Deserialize;

use aion_trust_claims::{
    BackgroundCheckBody, Claim, ClaimBody, EducationBody, EmploymentBody, TrustAnchor, Validity,
};
use aion_trust_core::Timestamp;
use aion_trust_registry::Status;

use crate::state::{AppState, Shared};
use crate::view::{self, esc};

/// GET /issuer.
pub(crate) async fn page(State(state): State<Shared>) -> Html<String> {
    let body = match state.lock() {
        Ok(app) => issuer_body(&app, None),
        Err(_) => busy(),
    };
    view::page("Issuer", "/issuer", &body)
}

#[derive(Deserialize, Default)]
pub(crate) struct IssueForm {
    category: String,
    #[serde(default)]
    employer: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    start: String,
    #[serde(default)]
    end: String,
    #[serde(default)]
    rehire_eligible: String,
    #[serde(default)]
    institution: String,
    #[serde(default)]
    credential: String,
    #[serde(default)]
    conferred: String,
    #[serde(default)]
    degree_rank: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    result: String,
    #[serde(default)]
    performed: String,
}

/// POST /issuer/issue — sign a claim with the issuer accredited for its category and add it to
/// the wallet.
pub(crate) async fn issue(
    State(state): State<Shared>,
    Form(form): Form<IssueForm>,
) -> Html<String> {
    let body = match state.lock() {
        Ok(mut app) => match do_issue(&mut app, &form) {
            Ok(label) => issuer_body(
                &app,
                Some(ok(&format!("Issued “{}” into the wallet.", esc(&label)))),
            ),
            Err(e) => issuer_body(&app, Some(warn(&e))),
        },
        Err(_) => busy(),
    };
    view::page("Issuer", "/issuer", &body)
}

#[derive(Deserialize)]
pub(crate) struct ClaimRef {
    claim_id: String,
}

/// POST /issuer/revoke.
pub(crate) async fn revoke(State(state): State<Shared>, Form(f): Form<ClaimRef>) -> Redirect {
    if let Ok(mut app) = state.lock() {
        let epoch = app.epoch;
        app.registry.revoke(&f.claim_id, epoch);
    }
    Redirect::to("/issuer")
}

/// POST /issuer/advance-epoch — bump the registry epoch (lets an accreditation lapse demo).
pub(crate) async fn advance_epoch(State(state): State<Shared>) -> Redirect {
    if let Ok(mut app) = state.lock() {
        app.epoch += 1;
        let e = app.epoch;
        app.registry.set_epoch(e);
    }
    Redirect::to("/issuer")
}

/// Issue the claim; returns the human label on success.
fn do_issue(app: &mut AppState, form: &IssueForm) -> Result<String, String> {
    let body = body_from_form(form)?;
    let category = form.category.clone();
    // Prefer the issuer accredited for this category; fall back to any issuer otherwise. A
    // fallback signature is authentic but not authoritative — the verifier shows it as
    // self-asserted and (for required categories) rejects it. So the fallback is a demo
    // affordance, never a way to launder authority.
    let key = app
        .issuers
        .iter()
        .find(|(_, s)| s.categories.contains(&category))
        .map(|(k, _)| k.clone())
        .or_else(|| app.issuers.keys().next().cloned())
        .ok_or_else(|| "no issuer configured".to_string())?;
    let did = app.wallet.did();
    let validity = Validity {
        from: Timestamp(0),
        until: None,
    };
    let claim = {
        let slot = app.issuers.get(&key).ok_or("issuer vanished")?;
        Claim::issue(&slot.identity, &did, validity, body).map_err(|e| e.to_string())?
    };
    let label = label_for(&category);
    app.claim_labels
        .insert(claim.claim_id().as_str().to_string(), label.clone());
    app.wallet.add(claim);
    Ok(label)
}

/// Map the issue form to a typed [`ClaimBody`] for one of the three demo categories.
fn body_from_form(form: &IssueForm) -> Result<ClaimBody, String> {
    let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
    match form.category.as_str() {
        "employment" => Ok(ClaimBody::Employment(EmploymentBody {
            employer: form.employer.clone(),
            title: form.title.clone(),
            employment_type: "full_time".into(),
            start: form.start.clone(),
            end: opt(&form.end),
            rehire_eligible: form.rehire_eligible == "on",
        })),
        "education" => Ok(ClaimBody::Education(EducationBody {
            institution: form.institution.clone(),
            credential: form.credential.clone(),
            conferred: form.conferred.clone(),
            aion_edu_ref: None,
            degree_rank: form.degree_rank.parse().ok(),
        })),
        "background_check" => Ok(ClaimBody::BackgroundCheck(BackgroundCheckBody {
            provider: form.provider.clone(),
            scope: form
                .scope
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            result: if form.result.is_empty() {
                "clear".into()
            } else {
                form.result.clone()
            },
            performed: form.performed.clone(),
            valid_until: None,
            jurisdiction: "US".into(),
            fcra_compliant: true,
        })),
        other => Err(format!("unknown category: {other}")),
    }
}

fn label_for(category: &str) -> String {
    match category {
        "employment" => "Employment claim",
        "education" => "Education claim",
        "background_check" => "Background check",
        _ => "Claim",
    }
    .to_string()
}

/// The issuer page body: standings, issue forms, and the issued-claims table.
fn issuer_body(app: &AppState, flash: Option<String>) -> String {
    let head = flash.unwrap_or_default();
    let now = Timestamp::now();
    let mut slots: Vec<_> = app.issuers.values().collect();
    slots.sort_by(|a, b| a.label.cmp(&b.label));
    let standings: String = slots
        .iter()
        .map(|s| {
            let cat = s.categories.first().map(String::as_str).unwrap_or("");
            let st = app.registry.standing(&s.identity.did(), cat, now);
            let badge = if st.accredited {
                r#"<span class="badge ok">accredited</span>"#
            } else {
                r#"<span class="badge warn">self-asserted</span>"#
            };
            format!(
                r#"<tr><td>{}</td><td>{}</td><td class="mono">{}</td><td>{badge}</td></tr>"#,
                esc(&s.label),
                esc(cat),
                esc(s.identity.did().as_str()),
            )
        })
        .collect();
    let rows: String = app
        .wallet
        .claims()
        .iter()
        .map(|c| claim_row(app, c))
        .collect();
    format!(
        r#"{head}<p class="kicker">issuer · console</p><h1>Issue & revoke claims</h1>
<div class="panel"><h2>Registered issuers · epoch {epoch}</h2>
<table><thead><tr><th>issuer</th><th>category</th><th>did</th><th>standing</th></tr></thead><tbody>{standings}</tbody></table>
<form method="post" action="/issuer/advance-epoch" style="margin-top:1rem"><button class="button ghost" type="submit">Advance epoch →</button></form></div>
{forms}
<div class="panel"><h2>Issued claims (in the candidate's wallet)</h2>
<table><thead><tr><th>claim</th><th>category</th><th>status</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>"#,
        epoch = app.epoch,
        forms = issue_forms(),
    )
}

fn claim_row(app: &AppState, c: &Claim) -> String {
    let id = c.claim_id().as_str();
    let label = app.claim_labels.get(id).cloned().unwrap_or_default();
    let revoked = matches!(app.registry.ledger_record(id).status, Status::Revoked);
    let (badge, action) = if revoked {
        (
            r#"<span class="badge bad">revoked</span>"#.to_string(),
            String::new(),
        )
    } else {
        (
            r#"<span class="badge ok">issued</span>"#.to_string(),
            format!(
                r#"<form method="post" action="/issuer/revoke"><input type="hidden" name="claim_id" value="{}"><button class="button danger" type="submit">Revoke</button></form>"#,
                esc(id),
            ),
        )
    };
    format!(
        r#"<tr><td>{}<br><span class="mono">{}</span></td><td>{}</td><td>{badge}</td><td>{action}</td></tr>"#,
        esc(&label),
        esc(id),
        esc(c.category()),
    )
}

/// The three issue forms (employment / education / background check).
fn issue_forms() -> &'static str {
    r#"<div class="grid">
<form class="stack panel" method="post" action="/issuer/issue"><h3>Issue employment</h3>
<input type="hidden" name="category" value="employment">
<label class="field">Employer<input type="text" name="employer" value="Acme Corp"></label>
<label class="field">Title<input type="text" name="title" value="Staff Engineer"></label>
<label class="field">Start<input type="text" name="start" value="2024-09-01"></label>
<label class="checks-inline"><input type="checkbox" name="rehire_eligible" value="on" checked> rehire eligible</label>
<button class="button" type="submit">Issue →</button></form>
<form class="stack panel" method="post" action="/issuer/issue"><h3>Issue education</h3>
<input type="hidden" name="category" value="education">
<label class="field">Institution<input type="text" name="institution" value="State University"></label>
<label class="field">Credential<input type="text" name="credential" value="B.S. Computer Science"></label>
<label class="field">Conferred<input type="text" name="conferred" value="2019-05-20"></label>
<label class="field">Degree rank (0–5)<input type="number" name="degree_rank" value="3"></label>
<button class="button" type="submit">Issue →</button></form>
<form class="stack panel" method="post" action="/issuer/issue"><h3>Issue background check</h3>
<input type="hidden" name="category" value="background_check">
<label class="field">Provider<input type="text" name="provider" value="TrustScreen"></label>
<label class="field">Scope (comma-separated)<input type="text" name="scope" value="criminal,identity"></label>
<label class="field">Result<input type="text" name="result" value="clear"></label>
<label class="field">Performed<input type="text" name="performed" value="2026-05-10"></label>
<button class="button" type="submit">Issue →</button></form></div>"#
}

/// NOTE: `msg` is treated as **trusted HTML** (callers embed links / pre-escaped labels). Never
/// pass unescaped user input — use [`warn`] (which escapes) for that.
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

    #[test]
    fn body_from_form_builds_each_category() {
        let mut f = IssueForm {
            category: "employment".into(),
            employer: "Acme".into(),
            title: "Eng".into(),
            start: "2021".into(),
            ..Default::default()
        };
        assert!(matches!(
            body_from_form(&f).unwrap(),
            ClaimBody::Employment(_)
        ));
        f.category = "education".into();
        f.degree_rank = "4".into();
        match body_from_form(&f).unwrap() {
            ClaimBody::Education(e) => assert_eq!(e.degree_rank, Some(4)),
            _ => panic!("expected education"),
        }
        f.category = "background_check".into();
        f.scope = "criminal, identity".into();
        match body_from_form(&f).unwrap() {
            ClaimBody::BackgroundCheck(b) => assert_eq!(b.scope, vec!["criminal", "identity"]),
            _ => panic!("expected background_check"),
        }
        f.category = "nonsense".into();
        assert!(body_from_form(&f).is_err());
    }

    #[test]
    fn issue_then_revoke_updates_wallet_and_status() {
        let mut app = AppState::seed();
        let before = app.wallet.claims().len();
        let form = IssueForm {
            category: "employment".into(),
            employer: "Globex".into(),
            title: "Director".into(),
            start: "2025-01-01".into(),
            ..Default::default()
        };
        do_issue(&mut app, &form).unwrap();
        assert_eq!(app.wallet.claims().len(), before + 1);
        // revoke the newest claim and confirm its ledger status flips
        let id = app
            .wallet
            .claims()
            .last()
            .unwrap()
            .claim_id()
            .as_str()
            .to_string();
        let epoch = app.epoch;
        app.registry.revoke(&id, epoch);
        assert!(matches!(
            app.registry.ledger_record(&id).status,
            Status::Revoked
        ));
        // and the issuer page shows the revoked badge
        assert!(issuer_body(&app, None).contains("revoked"));
    }

    #[test]
    fn advance_epoch_increments() {
        let mut app = AppState::seed();
        assert_eq!(app.epoch, 1);
        app.epoch += 1;
        app.registry.set_epoch(app.epoch);
        assert_eq!(app.epoch, 2);
    }
}
