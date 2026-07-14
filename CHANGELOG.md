# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Rule engine with 50 rules across three categories — security (20),
  caching (14), correctness (16) — every rule carrying a citation to the
  governing spec (RFC 9110/9111/9112, RFC 6265/6265bis, RFC 6797,
  RFC 7034, WHATWG Fetch/HTML, W3C CSP3/Referrer Policy) surfaced in all
  output formats and via `hdrlint explain <rule-id>`.
- Security rules: HSTS presence/grammar/max-age/plain-HTTP misuse, CSP
  presence and script-policy analysis ('unsafe-inline' with nonce/hash
  awareness, wildcard sources), nosniff, frame protection, cookie
  attributes (Secure/HttpOnly/SameSite, SameSite=None+Secure), CORS
  wildcard-with-credentials, and disclosure headers.
- Caching rules: Cache-Control grammar and directive conflicts (no-store
  vs max-age/public, public+private, private+s-maxage), delta-seconds
  validation, typo'd/request-only directives, Expires validity and
  max-age override, Pragma, Age, Vary: *, unquoted ETags, and
  Last-Modified after Date (compared against the Date header, never the
  wall clock).
- Correctness rules: duplicate singleton fields, Content-Length /
  Transfer-Encoding smuggling shapes, forbidden Content-Length statuses,
  media-type and HTTP-date grammar (including obsolete date forms),
  redirect Location, 405 Allow, Retry-After, field name/value byte
  validity, and obs-fold.
- Offline capture parsing: raw dumps (`curl -i`, `curl -sD -`,
  `curl -siL` redirect chains, devtools header pastes) and HAR 1.2
  archives with per-entry HTTPS detection; `-` reads stdin.
- `check` command with text, JSON (`schema_version: 1`), and GitHub
  Actions annotation output; `--fail-on error|warn|info|never` threshold;
  `--disable`/`--only` rule filters that reject unknown IDs; `--http`
  transport context; exit codes 0/1/2/3.
- `rules` (text/JSON catalog) and `explain` (advice + cited text URL)
  subcommands; reference docs `docs/rules.md` and `docs/inputs.md`.
- Runnable examples (`examples/ci-gate.sh`, hardened and regressed
  captures, redirect chain, HAR) — the hardened capture is proven clean
  by an integration test against the full catalog.
- 88 deterministic offline tests (unit + in-process CLI integration)
  and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/hdrlint/releases/tag/v0.1.0
