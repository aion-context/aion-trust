#!/usr/bin/env bash
# Gate: no secrets/keys committed to the tree. High-precision patterns only.
set -uo pipefail
cd "$(dirname "$0")/../.."

# Scan tracked files if in git, else the working tree (excluding noise).
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files=$(git ls-files)
else
  files=$(find . -type f -not -path './.git/*' -not -path './target/*')
fi
[ -z "$files" ] && { echo "  (no files to scan)"; exit 0; }

pattern='-----BEGIN [A-Z ]*PRIVATE KEY|sk-ant-[A-Za-z0-9_-]{20,}|sk_(live|test)_[A-Za-z0-9]{16,}|sk_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|(ELEVEN_LABS_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY)=[A-Za-z0-9/_+-]{12,}'

hits=$(printf '%s\n' "$files" | xargs -r grep -nIE -e "$pattern" 2>/dev/null | grep -viE '\.example|placeholder|your_.*_here|REDACTED' || true)
if [ -n "$hits" ]; then
  echo "  POSSIBLE SECRET committed:"
  echo "$hits" | sed -E 's/=.{6,}/=<REDACTED>/' | sed 's/^/    /'
  echo "  → Use .gitignored env files / secret managers; never commit keys."
  exit 1
fi
echo "  no secrets/keys detected"
exit 0
