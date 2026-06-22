//! aion-trust — the Phase 1 kernel CLI: `keygen`, `issue`, `present`, `verify`.
//! Identities are 32-byte secrets (hex); claims and presentations are JSON artifacts.

use std::path::{Path, PathBuf};

use std::collections::HashMap;

use aion_trust_claims::{
    build_presentation, verify_presentation_with_predicates, verify_presentation_with_store,
    BackgroundCheckBody, Claim, ClaimBody, EmploymentBody, FieldSelector, IssuerDirectory,
    NonceStore, PredicateOp, PredicateRequest, Presentation, Validity,
};
use aion_trust_core::identity::verifying_key_from_hex;
use aion_trust_core::{Did, Identity, Result, Timestamp, TrustError};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "aion-trust",
    about = "Verifiable résumé kernel — issue, present, verify."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh identity (prints the secret and its did).
    Keygen {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Issue (sign) an employment claim for a subject did.
    Issue {
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        employer: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        start: String,
        #[arg(long)]
        end: Option<String>,
        #[arg(long, default_value = "full_time")]
        employment_type: String,
        #[arg(long)]
        rehire: bool,
        #[arg(long)]
        valid_until: Option<i64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Issue (sign) a background-check claim for a subject did.
    IssueCheck {
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        provider: String,
        #[arg(long = "scope", required = true)]
        scope: Vec<String>,
        #[arg(long, default_value = "clear")]
        result: String,
        #[arg(long)]
        performed: String,
        #[arg(long)]
        valid_until: Option<String>,
        #[arg(long, default_value = "US")]
        jurisdiction: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Build a presentation: a subject-signed bundle of claims for one verifier.
    Present {
        #[arg(long)]
        subject: String,
        #[arg(long)]
        audience: String,
        #[arg(long, default_value = "application")]
        purpose: String,
        #[arg(long = "claim", required = true)]
        claims: Vec<PathBuf>,
        /// Reveal only some fields of a claim: `--reveal <claim_id>:field,field`. A claim with
        /// no `--reveal` entry discloses all its fields. Repeatable.
        #[arg(long = "reveal")]
        reveal: Vec<String>,
        #[arg(long, default_value_t = 604_800)]
        expires_in: i64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a presentation offline against a set of recognized issuer keys.
    Verify {
        #[arg(long)]
        presentation: PathBuf,
        #[arg(long = "as")]
        audience: String,
        #[arg(long = "issuer-key")]
        issuer_keys: Vec<String>,
        /// Persisted single-use nonce store (JSON). When given, a replayed presentation is
        /// rejected; the file is created if absent and updated on an accepted presentation.
        #[arg(long = "nonce-store")]
        nonce_store: Option<PathBuf>,
        /// Require a predicate: `--predicate <category>:<field>:<ge|le|gt|lt|eq>:<bound>`
        /// (optionally `:<schema_id>` to pin an ordinal scale). Repeatable.
        #[arg(long = "predicate")]
        predicates: Vec<String>,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { out } => keygen(out),
        Cmd::Issue { .. } => issue(cli.cmd),
        Cmd::IssueCheck { .. } => issue_check(cli.cmd),
        Cmd::Present { .. } => present(cli.cmd),
        Cmd::Verify { .. } => verify(cli.cmd),
    }
}

fn keygen(out: Option<PathBuf>) -> Result<()> {
    let id = Identity::generate();
    let secret = id.secret_hex();
    println!("did:    {}", id.did());
    println!(
        "pubkey: {}",
        aion_trust_core::encoding::to_hex(&id.verifying_key().to_bytes())
    );
    if let Some(path) = out {
        std::fs::write(&path, &secret)?;
        println!("secret: written to {}", path.display());
    } else {
        println!("secret: {secret}");
    }
    Ok(())
}

fn issue(cmd: Cmd) -> Result<()> {
    let Cmd::Issue {
        issuer,
        subject,
        employer,
        title,
        start,
        end,
        employment_type,
        rehire,
        valid_until,
        out,
    } = cmd
    else {
        unreachable!()
    };
    let issuer = load_identity(&issuer)?;
    let validity = Validity {
        from: Timestamp::now(),
        until: valid_until.map(Timestamp),
    };
    let body = ClaimBody::Employment(EmploymentBody {
        employer,
        title,
        employment_type,
        start,
        end,
        rehire_eligible: rehire,
    });
    let claim = Claim::issue(&issuer, &Did::from_string(subject), validity, body)
        .map_err(|e| TrustError::Decode(format!("issue failed: {e}")))?;
    emit(&claim, out)
}

fn issue_check(cmd: Cmd) -> Result<()> {
    let Cmd::IssueCheck {
        issuer,
        subject,
        provider,
        scope,
        result,
        performed,
        valid_until,
        jurisdiction,
        out,
    } = cmd
    else {
        unreachable!()
    };
    let issuer = load_identity(&issuer)?;
    let validity = Validity {
        from: Timestamp::now(),
        until: None,
    };
    let body = ClaimBody::BackgroundCheck(BackgroundCheckBody {
        provider,
        scope,
        result,
        performed,
        valid_until,
        jurisdiction,
        fcra_compliant: true,
    });
    let claim = Claim::issue(&issuer, &Did::from_string(subject), validity, body)
        .map_err(|e| TrustError::Decode(format!("issue failed: {e}")))?;
    emit(&claim, out)
}

fn present(cmd: Cmd) -> Result<()> {
    let Cmd::Present {
        subject,
        audience,
        purpose,
        claims,
        reveal,
        expires_in,
        out,
    } = cmd
    else {
        unreachable!()
    };
    let subject = load_identity(&subject)?;
    let selectors = parse_reveal(&reveal)?;
    let mut disclosed = Vec::with_capacity(claims.len());
    for path in &claims {
        let claim = read_json::<Claim>(path)?;
        let selector = selectors
            .get(claim.claim_id().as_str())
            .cloned()
            .unwrap_or(FieldSelector::All);
        disclosed.push(
            claim
                .disclose(&selector)
                .map_err(|e| TrustError::Decode(format!("disclose failed: {e}")))?,
        );
    }
    let now = Timestamp::now();
    // 24-byte nonce (two 12-byte CSPRNG draws) — over the verifier's 16-byte floor.
    let n1 = aion_context::crypto::generate_nonce();
    let n2 = aion_context::crypto::generate_nonce();
    let nonce: Vec<u8> = n1.iter().chain(n2.iter()).copied().collect();
    let presentation = build_presentation(
        &subject,
        &Did::from_string(audience),
        &purpose,
        &nonce,
        now,
        now.plus_seconds(expires_in),
        disclosed,
    );
    emit(&presentation, out)
}

/// Parse `--predicate <category>:<field>:<op>:<bound>[:<schema_id>]` entries.
fn parse_predicates(entries: &[String]) -> Result<Vec<PredicateRequest>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let parts: Vec<&str> = entry.split(':').collect();
        let [category, field, op, bound, rest @ ..] = parts.as_slice() else {
            return Err(TrustError::Decode(format!(
                "--predicate needs <category>:<field>:<op>:<bound>: {entry}"
            )));
        };
        out.push(PredicateRequest {
            category: (*category).to_string(),
            field: (*field).to_string(),
            op: parse_op(op)?,
            bound: parse_bound(bound),
            scale_version: rest.first().map(|s| (*s).to_string()),
        });
    }
    Ok(out)
}

fn parse_op(op: &str) -> Result<PredicateOp> {
    match op {
        "ge" => Ok(PredicateOp::Ge),
        "le" => Ok(PredicateOp::Le),
        "gt" => Ok(PredicateOp::Gt),
        "lt" => Ok(PredicateOp::Lt),
        "eq" => Ok(PredicateOp::Eq),
        other => Err(TrustError::Decode(format!("unknown predicate op: {other}"))),
    }
}

/// A bound is a number if it parses as one, else a (date/text) string.
fn parse_bound(bound: &str) -> serde_json::Value {
    match bound.parse::<i64>() {
        Ok(n) => serde_json::Value::from(n),
        Err(_) => serde_json::Value::from(bound),
    }
}

/// Parse `--reveal <claim_id>:field,field` entries into a per-claim field selector.
fn parse_reveal(entries: &[String]) -> Result<HashMap<String, FieldSelector>> {
    let mut map = HashMap::new();
    for entry in entries {
        let (id, fields) = entry
            .split_once(':')
            .ok_or_else(|| TrustError::Decode(format!("--reveal needs <id>:<fields>: {entry}")))?;
        let keys: Vec<String> = fields.split(',').map(|s| s.trim().to_string()).collect();
        map.insert(id.to_string(), FieldSelector::Only(keys));
    }
    Ok(map)
}

fn verify(cmd: Cmd) -> Result<()> {
    let Cmd::Verify {
        presentation,
        audience,
        issuer_keys,
        nonce_store,
        predicates,
    } = cmd
    else {
        unreachable!()
    };
    let p = read_json::<Presentation>(&presentation)?;
    let mut directory = IssuerDirectory::new();
    for key in &issuer_keys {
        directory.register(verifying_key_from_hex(key)?);
    }
    let audience = Did::from_string(audience);
    let now = Timestamp::now();
    let preds = parse_predicates(&predicates)?;
    let report = match nonce_store {
        Some(path) => {
            let mut store = JsonFileNonceStore::load(&path)?;
            let r =
                verify_presentation_with_store(&p, &audience, now, &directory, &mut store, &preds)?;
            store.save(&path)?;
            r
        }
        None => verify_presentation_with_predicates(&p, &audience, now, &directory, false, &preds)?,
    };
    for c in &report.checks {
        let mark = if c.passed { "✓" } else { "✗" };
        println!(
            "  {mark} {}{}",
            c.name,
            if c.detail.is_empty() {
                String::new()
            } else {
                format!("  ({})", c.detail)
            }
        );
    }
    println!(
        "\n{}",
        if report.accepted {
            "ACCEPTED"
        } else {
            "REJECTED"
        }
    );
    std::process::exit(if report.accepted { 0 } else { 1 });
}

/// A file-backed [`NonceStore`] for the CLI demo: the verifier remembers accepted
/// `(audience, nonce)` pairs across runs, so a replayed presentation is rejected. Persistence
/// (and any expiry-based pruning) is a deployment concern; this keeps every entry.
#[derive(Default, Serialize, Deserialize)]
struct JsonFileNonceStore {
    seen: Vec<NonceRecord>,
}

#[derive(Serialize, Deserialize)]
struct NonceRecord {
    audience: String,
    nonce: String,
    expires_at: i64,
}

impl JsonFileNonceStore {
    fn load(path: &Path) -> Result<Self> {
        if path.is_file() {
            Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
        } else {
            Ok(Self::default())
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

impl NonceStore for JsonFileNonceStore {
    fn seen(&self, audience: &Did, nonce: &str) -> bool {
        self.seen
            .iter()
            .any(|r| r.audience == audience.as_str() && r.nonce == nonce)
    }

    fn record(&mut self, audience: &Did, nonce: &str, expires_at: Timestamp) {
        self.seen.push(NonceRecord {
            audience: audience.as_str().to_string(),
            nonce: nonce.to_string(),
            expires_at: expires_at.0,
        });
    }
}

/// Load an identity from a hex secret, or from a file containing one.
fn load_identity(arg: &str) -> Result<Identity> {
    let path = Path::new(arg);
    let secret = if path.is_file() {
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        arg.to_string()
    };
    Identity::from_secret_hex(&secret)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn emit<T: Serialize>(value: &T, out: Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    match out {
        Some(path) => {
            std::fs::write(&path, json)?;
            eprintln!("written to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}
