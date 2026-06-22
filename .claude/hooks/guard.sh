#!/usr/bin/env bash
# PreToolUse guard for Write|Edit. Hard-blocks (exit 2) writes that contain a secret/private
# key; advises (exit 0) on the PII-on-ledger invariant. Reads the tool-call JSON on stdin.
input=$(cat)

fp=$(printf '%s' "$input" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))
except Exception: print("")' 2>/dev/null)
content=$(printf '%s' "$input" | python3 -c 'import sys,json
try:
  ti=json.load(sys.stdin).get("tool_input",{})
  sys.stdout.write(ti.get("content") or ti.get("new_string") or "")
except Exception: pass' 2>/dev/null)

[ -z "$fp" ] && exit 0

SECRET='-----BEGIN [A-Z ]*PRIVATE KEY|sk-ant-[A-Za-z0-9_-]{20,}|sk_(live|test)_[A-Za-z0-9]{16,}|sk_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|(ELEVEN_LABS_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY)=[A-Za-z0-9/_+-]{12,}'

# ── HARD BLOCK: secrets / private keys ──────────────────────────────
if printf '%s' "$content" | grep -qE -e "$SECRET"; then
  echo "BLOCKED: $fp appears to contain a hardcoded secret or private key. aion-trust never commits secrets — use a .gitignored env file or a secret manager. (.claude/hooks/guard.sh)" >&2
  exit 2
fi

# ── ADVISORY: PII heading for the ledger (heuristic, non-blocking) ──
case "$fp" in
  *ledger*|*registry*|*status*)
    if printf '%s' "$content" | grep -qiE '\b(ssn|date_of_birth|dob|birth_?date|full_?name|home_?address|email|phone_?number|passport)\b'; then
      echo "INVARIANT WATCH: $fp is ledger/registry/status code and references PII-like fields. aion-trust's core rule is NO PII ON THE LEDGER — keep PII in the wallet/claim body. (docs/ARCHITECTURE.md#the-privacy-model)" >&2
    fi ;;
esac
exit 0
