#!/usr/bin/env bash
# PostToolUse hook for Write|Edit: auto-format a touched Rust file (best-effort, never fails
# the tool call). Reads the tool-call JSON on stdin.
fp=$(cat | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))
except Exception: print("")' 2>/dev/null)

case "$fp" in
  *.rs) ;;
  *) exit 0 ;;
esac
[ -f "$fp" ] || exit 0
command -v rustfmt >/dev/null 2>&1 || exit 0
rustfmt --edition 2021 "$fp" >/dev/null 2>&1 || true
exit 0
