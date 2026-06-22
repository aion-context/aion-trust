//! HTML rendering: the shared page chrome and small pure view helpers.
//!
//! All dynamic values are passed through [`esc`] before they reach HTML — a claim body is the
//! operator's own PII rendered to their own loopback browser, but it must never be able to
//! inject markup or script. The helpers here are pure (no I/O, no state) and unit-tested, so
//! they stay in the mutation-testing scope while the handler glue is excluded.

use aion_trust_claims::Check;
use axum::response::Html;

/// HTML-escape text destined for element content or an attribute value.
pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The five surfaces, in nav order: (path, label).
const SURFACES: [(&str, &str); 5] = [
    ("/", "Home"),
    ("/issuer", "Issuer"),
    ("/wallet", "Wallet"),
    ("/verify", "Verify"),
    ("/walkthrough", "Walkthrough"),
];

/// Wrap a body fragment in the shared shell (head, fonts, nav, footer motto). `active` is the
/// path of the current surface, highlighted in the nav.
pub(crate) fn page(title: &str, active: &str, body: &str) -> Html<String> {
    let nav: String = SURFACES
        .iter()
        .map(|(path, label)| {
            let cls = if *path == active { "active" } else { "" };
            format!(r#"<a class="{cls}" href="{path}">{label}</a>"#)
        })
        .collect();
    Html(format!(
        r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>aion-trust · {title}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Afacad:ital,wght@0,400..700;1,400..700&family=Bricolage+Grotesque:opsz,wght@12..96,300..800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/app.css">
</head><body>
<header class="top"><span class="brand">aion<span class="dot">·</span>trust</span><nav class="surfaces">{nav}</nav></header>
<main class="wrap">{body}</main>
<footer class="motto">Do the work once. Prove it forever.</footer>
</body></html>"#,
        title = esc(title),
    ))
}

/// One verification check as a row: mint ✓ when passed, coral ✗ when failed.
pub(crate) fn check_row(check: &Check) -> String {
    let (cls, mark) = if check.passed {
        ("is-valid", "✓")
    } else {
        ("is-invalid", "✗")
    };
    let detail = if check.detail.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="detail">{}</span>"#, esc(&check.detail))
    };
    format!(
        r#"<div class="check-row {cls}"><span class="mark">{mark}</span><span class="name">{}</span>{detail}</div>"#,
        esc(&check.name),
    )
}

/// The big ACCEPTED / REJECTED verdict badge.
pub(crate) fn verdict(accepted: bool) -> String {
    if accepted {
        r#"<div class="verdict accepted">ACCEPTED</div>"#.to_string()
    } else {
        r#"<div class="verdict rejected">REJECTED</div>"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_neutralizes_markup() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
        assert_eq!(esc("plain"), "plain"); // pass-through, kills "-> empty" mutants
    }

    #[test]
    fn check_row_reflects_pass_and_fail() {
        let pass = Check {
            name: "unexpired".into(),
            passed: true,
            detail: "now<exp".into(),
        };
        let row = check_row(&pass);
        assert!(row.contains("is-valid") && row.contains('✓') && row.contains("unexpired"));
        assert!(row.contains("now&lt;exp")); // detail is escaped
        let fail = Check {
            name: "claim not revoked".into(),
            passed: false,
            detail: String::new(),
        };
        let row = check_row(&fail);
        assert!(row.contains("is-invalid") && row.contains('✗'));
        assert!(!row.contains("detail")); // empty detail → no span
    }

    #[test]
    fn verdict_distinguishes_outcomes() {
        assert!(verdict(true).contains("ACCEPTED") && verdict(true).contains("accepted"));
        assert!(verdict(false).contains("REJECTED") && verdict(false).contains("rejected"));
        assert_ne!(verdict(true), verdict(false));
    }

    #[test]
    fn page_marks_active_surface_and_escapes_title() {
        let html = page("<x>", "/verify", "body-here").0;
        assert!(html.contains("aion-trust · &lt;x&gt;")); // title escaped
        assert!(html.contains(r#"<a class="active" href="/verify">Verify</a>"#));
        assert!(html.contains("body-here"));
        assert!(html.contains("Do the work once"));
    }
}
