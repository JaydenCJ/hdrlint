# Contributing to hdrlint

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else.

```bash
git clone https://github.com/JaydenCJ/hdrlint && cd hdrlint
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives every subcommand, input
format, and exit code against the deterministic captures in `examples/`;
it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (88 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (parsers and rules never touch the filesystem — only the CLI
   layer does I/O).

## Ground rules

- Keep dependencies at zero — hdrlint is standard library only, and that
  is a feature. Adding one needs strong justification in the PR.
- No network calls, ever. hdrlint lints captures; it must never fetch.
  No telemetry.
- Rules are data plus one pure function. A new rule needs: a stable
  lowercase-hyphen ID, a severity argued in the PR, a **citation to the
  governing spec text** (rule without citation = rejected), remediation
  advice for `explain`, a test for both the firing and passing shapes,
  and a regenerated table row in `docs/rules.md`.
- Never cite a section number you have not read. Wrong citations are
  worse than no tool at all.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical reports,
  including all orderings.

## Reporting bugs

Include the output of `hdrlint version`, the full command you ran, and a
minimal capture that reproduces the problem (redact values if needed —
usually only the header names and shapes matter). For a wrong-citation or
wrong-severity report, quote the spec text you believe applies; those are
treated as high-priority bugs.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
