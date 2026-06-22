//! aion-trust — the Phase 1 kernel CLI: `keygen`, `issue`, `present`, `verify`.
//! Identities are 32-byte secrets (hex); claims and presentations are JSON artifacts.

use std::path::{Path, PathBuf};

use aion_trust_claims::{
    build_presentation, verify_presentation, BackgroundCheckBody, Claim, ClaimBody, EmploymentBody,
    IssuerDirectory, Presentation, Validity,
};
use aion_trust_core::identity::verifying_key_from_hex;
use aion_trust_core::{Did, Identity, Result, Timestamp, TrustError};
use clap::{Parser, Subcommand};
use serde::Serialize;

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
        expires_in,
        out,
    } = cmd
    else {
        unreachable!()
    };
    let subject = load_identity(&subject)?;
    let mut loaded = Vec::with_capacity(claims.len());
    for path in &claims {
        loaded.push(read_json::<Claim>(path)?);
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
        loaded,
    );
    emit(&presentation, out)
}

fn verify(cmd: Cmd) -> Result<()> {
    let Cmd::Verify {
        presentation,
        audience,
        issuer_keys,
    } = cmd
    else {
        unreachable!()
    };
    let p = read_json::<Presentation>(&presentation)?;
    let mut directory = IssuerDirectory::new();
    for key in &issuer_keys {
        directory.register(verifying_key_from_hex(key)?);
    }
    let report = verify_presentation(
        &p,
        &Did::from_string(audience),
        Timestamp::now(),
        &directory,
        false,
    )?;
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
