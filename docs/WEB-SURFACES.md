# Web surfaces (`aion-trust-web`)

Phase 5 makes the system tangible: one local axum app presenting the three actors as three
surfaces — an **issuer console**, a **candidate wallet**, and an **employer verifier** — plus a
live **walkthrough** that shows a verified claim turn red the instant its issuer revokes it.

```
cargo run -p aion-trust-cli -- serve --port 8080
# then open http://127.0.0.1:8080  (try /walkthrough first)
```

> ## ⚠ LOCAL SINGLE-OPERATOR DEMO — NOT A HOSTED SERVICE, NOT A CUSTODY ARCHITECTURE
>
> This one process holds the operator's **own** issuer, accreditor, and candidate **secret keys
> in memory** for the session, binds to **loopback only** (`127.0.0.1`), writes nothing to disk,
> and discards all state on exit (or via the Reset button). It co-locates three trust domains in
> one binary purely for demonstration.
>
> **That co-location is the one thing not to copy.** In a real deployment the three surfaces are
> three *different parties on three different machines*: the **wallet runs on the subject's own
> device** (their keys and PII never leave it except inside a presentation they build); the
> **issuer** runs its own signing service; the **verifier** holds only public keys plus the
> registry. Server-side custody of *many subjects'* private keys is precisely the centralized
> model aion-trust exists to refute (see [`ARCHITECTURE.md`](ARCHITECTURE.md#the-privacy-model),
> invariants #1 and #2). The aion-context **registry holds no PII in any deployment** — that is
> unchanged here.

## Surfaces & routes

| Surface | Routes | What it does |
|---|---|---|
| Home | `GET /` | Links the surfaces; Reset control (`POST /api/reset`). |
| Issuer console | `GET /issuer`, `POST /issuer/issue`, `POST /issuer/revoke`, `POST /issuer/advance-epoch` | Attest a fact (sign a claim into the wallet), revoke a claim, advance the registry epoch. Shows each issuer's accreditation **standing**. |
| Candidate wallet | `GET /wallet`, `POST /wallet/present`, `POST /wallet/disclose`, `POST /wallet/satisfy` | Build a presentation: full claims, a chosen subset of fields, or a predicate proof (minimal disclosure). |
| Employer verifier | `GET /verify`, `POST /verify/run` | Verify the pending presentation offline against the registry; render the report check-by-check with an ACCEPTED/REJECTED verdict. |
| Walkthrough | `GET /walkthrough`, `GET /walkthrough/stream` (SSE) | Scripted: issue → present → verify (green) → revoke → re-present → verify (red). |
| Static | `GET /app.css`, `GET /favicon.svg` | Embedded assets (the `site/` design tokens). |

## How it stays honest (privacy guardrails enforced in code)

- **Loopback only.** The bind address is a hardcoded `127.0.0.1` constant (`lib.rs`), never
  configurable to `0.0.0.0`.
- **No persistence.** All state is `Arc<Mutex<AppState>>` in process memory (`state.rs`); the app
  opens no database and writes no wallet/claim/secret file. Reset re-seeds in place.
- **No key ever leaves the lock.** Only `did:` strings and hex *verifying* keys are rendered;
  `Identity::secret_hex()` is never reachable from a handler's output. A test
  (`no_surface_leaks_a_secret_key`) renders every surface and asserts no secret appears.
- **No body to the verifier except inside a subject-built presentation.** Rendering the
  operator's own claim fields in the issuer/wallet UI is local sovereignty; every value is
  HTML-escaped (`view::esc`).
- **No PII in logs.** Handlers never `{:?}` a `Presentation`/`Claim`/`ClaimBody`; the nonce store
  records only `(audience, nonce)` + expiry.
- **Epoch-freeze.** Each verdict holds the state lock across the whole `set_epoch → verify`
  section (synchronous), so a verification always computes at one consistent registry epoch.

## Architecture notes

- A library crate (`aion-trust-web`) exposing `serve(port)`; the runnable entry is the existing
  `aion-trust` CLI's `serve` subcommand. Mirrors the `aion-edu-web` reference (axum + tokio +
  tokio-stream; HTML/`Json`/SSE; no templating crate — HTML is built by small pure helpers in
  `view.rs`, all dynamic values escaped).
- The web crate is **glue** and is excluded from mutation testing, **except** its pure logic
  (`view.rs` rendering, `parse.rs` form/predicate parsing), which stays at the 0-survivor bar.
