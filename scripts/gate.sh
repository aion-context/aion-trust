#!/usr/bin/env bash
# aion-trust quality gates — the definition of done. Non-zero exit = a gate failed.
# Runs the doc/secret gates always; the cargo gates once a Rust workspace exists.
# Usage: scripts/gate.sh
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
hr() { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
ok() { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
no() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; fail=1; }
gate() { hr "$1"; shift; if "$@"; then ok "passed"; else no "FAILED"; fi; }
skip() { hr "$1"; printf '  \033[2m– skipped: %s\033[0m\n' "$2"; }

# ── Always-on gates (guard docs + config even before code) ──────────
gate "no secrets in the tree"            scripts/gates/secret-scan.sh
gate "no PII in ledger/registry/status"  scripts/gates/pii-ledger-scan.sh

# ── Rust gates (once the workspace exists) ──────────────────────────
if [ -f Cargo.toml ]; then
  gate "cargo fmt --check"   cargo fmt --all -- --check
  gate "clippy -D warnings"  cargo clippy --all-targets --all-features -- -D warnings
  gate "cargo test --all"    cargo test --all --quiet
  if command -v cargo-deny >/dev/null 2>&1; then
    gate "cargo deny check"  cargo deny check
  else
    skip "cargo deny check" "cargo-deny not installed (cargo install cargo-deny)"
  fi
  if command -v cargo-mutants >/dev/null 2>&1; then
    # 0-survivors bar. --in-place because aion-context is a sibling path dep that does not
    # survive cargo-mutants' default /tmp copy; mutants reverts each change as it goes.
    gate "cargo mutants (0 survivors)" cargo mutants --in-place --no-shuffle --colors never
  else
    skip "cargo mutants" "cargo-mutants not installed (cargo install cargo-mutants)"
  fi
else
  skip "cargo fmt / clippy / test / deny / mutants" "no Cargo.toml yet (Phase 0: docs)"
fi

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[1;32m═══ GATE PASSED ═══\033[0m\n'
else
  printf '\033[1;31m═══ GATE FAILED ═══\033[0m\n'
fi
exit "$fail"
