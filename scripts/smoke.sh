#!/usr/bin/env bash
# End-to-end smoke test for hdrlint: builds the binary, then drives every
# subcommand, input format, and exit code against deterministic captures.
# No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/hdrlint"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/hdrlint) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "hdrlint 0.1.0" || fail "--version mismatch"

echo "3. hardened capture is clean (exit 0)"
OUT="$("$BIN" check "$ROOT/examples/good.txt")" || fail "good.txt should exit 0"
echo "$OUT" | grep -q "ok — no findings" || fail "clean verdict missing"

echo "4. regressed capture fails with cited findings (exit 1)"
set +e
OUT="$("$BIN" check "$ROOT/examples/bad.txt")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "bad.txt exited $CODE, want 1"
echo "$OUT" | grep -q "etag-malformed" || fail "etag finding missing"
echo "$OUT" | grep -q "RFC 9110 §8.8.3" || fail "RFC citation missing"
echo "$OUT" | grep -q "cache-no-store-conflict" || fail "caching conflict missing"
echo "$OUT" | grep -q "3 errors, 4 warnings, 5 notices" || fail "summary counts wrong"

echo "5. JSON report is machine-readable with citation URLs"
JSON="$("$BIN" check --format json "$ROOT/examples/bad.txt" || true)"
echo "$JSON" | grep -q '"tool": "hdrlint"' || fail "json envelope missing"
echo "$JSON" | grep -q '"schema_version": 1' || fail "schema version missing"
echo "$JSON" | grep -q 'rfc9110#section-8.8.3' || fail "citation URL missing"

echo "6. GitHub annotations format"
"$BIN" check --format github --fail-on never "$ROOT/examples/bad.txt" \
  | grep -q '^::error title=hdrlint etag-malformed::' || fail "github annotation missing"

echo "7. redirect chains lint every hop"
"$BIN" check --fail-on never "$ROOT/examples/redirect-chain.txt" \
  | grep -q "checked 2 responses" || fail "chain not split into responses"

echo "8. HAR input with per-entry scheme handling"
OUT="$("$BIN" check "$ROOT/examples/capture.har" || true)"
echo "$OUT" | grep -q "cors-wildcard-credentials" || fail "HAR https entry not linted"
echo "$OUT" | grep -q "hsts-over-http" || fail "HAR http entry scheme ignored"

echo "9. stdin, --only, and --disable"
printf 'HTTP/1.1 200 OK\r\nETag: bare\r\n\r\n' | "$BIN" check --only etag-malformed --fail-on never - \
  | grep -q "stdin#1" || fail "stdin capture not linted"
OUT="$("$BIN" check --only hsts-missing --fail-on never "$ROOT/examples/bad.txt")"
echo "$OUT" | grep -q "hsts-missing" || fail "--only dropped the requested rule"
echo "$OUT" | grep -q "etag-malformed" && fail "--only leaked other rules" || true
OUT="$("$BIN" check --disable etag-malformed --fail-on never "$ROOT/examples/bad.txt")"
echo "$OUT" | grep -q "etag-malformed" && fail "--disable did not silence the rule" || true
"$BIN" check --disable no-such-rule "$ROOT/examples/bad.txt" >/dev/null 2>&1 \
  && fail "unknown rule id accepted" || [ $? -eq 2 ] || fail "unknown rule id should exit 2"

echo "10. rules catalog and explain cite their specs"
"$BIN" rules | grep -q "rules total" || fail "rules listing broken"
"$BIN" rules --format json | grep -q '"id": "hsts-missing"' || fail "rules json broken"
"$BIN" explain content-length-transfer-encoding | grep -q "RFC 9112 §6.3" || fail "explain citation missing"

echo "11. usage and runtime error exit codes"
set +e
"$BIN" check --format yaml "$ROOT/examples/good.txt" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
"$BIN" check "$WORKDIR/does-not-exist.txt" >/dev/null 2>&1
[ $? -eq 3 ] || fail "missing file should exit 3"
set -e

echo "SMOKE OK"
