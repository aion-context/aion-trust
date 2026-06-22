#!/usr/bin/env bash
# Invariant gate: NO PII ON THE LEDGER.
# Fails if ledger / registry / status source mentions person-identifying fields.
# Heuristic but high-signal: the immutable layer must hold only keys, accreditation,
# schemas, and opaque claim status. PII belongs in the wallet/claim body.
set -uo pipefail
cd "$(dirname "$0")/../.."

# Files that represent the shared/immutable layer.
targets=$(grep -rliE 'ledger|registry|status' --include='*.rs' crates 2>/dev/null || true)
[ -z "$targets" ] && { echo "  (no ledger/registry/status Rust files yet — nothing to scan)"; exit 0; }

# PII tokens that must never appear in those structs.
pii='\b(ssn|social_security|date_of_birth|dob|birth_?date|full_?name|first_?name|last_?name|home_?address|street_?address|email|phone_?number|passport|drivers_?license|biometric)\b'

hits=$(grep -rniE "$pii" $targets 2>/dev/null | grep -viE '//|/\*|test|example|placeholder' || true)
if [ -n "$hits" ]; then
  echo "  PII-like fields found in ledger/registry/status code:"
  echo "$hits" | sed 's/^/    /'
  echo "  → Move PII into the wallet/claim body; the ledger holds only keys/status/schemas."
  echo "    (docs/ARCHITECTURE.md#the-privacy-model)"
  exit 1
fi
echo "  no PII fields in ledger/registry/status code"
exit 0
