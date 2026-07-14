#!/usr/bin/env bash
# ci-gate.sh — hdrlint as a CI gate, in three lines.
#
# The pattern: capture headers in your integration tests (curl -sD -, a
# saved HAR from a browser test, or any proxy dump), then let hdrlint's
# exit code decide the build. --format github turns each finding into an
# inline annotation on GitHub Actions with no marketplace action needed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BIN="${HDRLINT:-./hdrlint}"
if [ ! -x "$BIN" ]; then
  echo "building hdrlint…"
  go build -o hdrlint ./cmd/hdrlint
  BIN=./hdrlint
fi

echo "== 1. a hardened response passes (exit 0, build proceeds)"
"$BIN" check examples/good.txt

echo
echo "== 2. a regressed response fails the gate (exit 1) with annotations"
if "$BIN" check --format github --fail-on warn examples/bad.txt; then
  echo "unexpected: bad.txt passed"
  exit 1
else
  echo "(exit $? — this is what breaks the CI job)"
fi

echo
echo "== 3. report-only mode for adopting hdrlint incrementally"
"$BIN" check --fail-on never examples/bad.txt >/dev/null && echo "exit 0: findings reported, build unaffected"
