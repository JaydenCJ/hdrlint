# hdrlint examples

Deterministic captures plus one runnable script — everything works offline.

## good.txt

A fully hardened HTML response: HSTS, CSP with `frame-ancestors`,
`nosniff`, an explicit cache policy, a quoted ETag. It produces **zero
findings** and is the shape to aim for:

```bash
hdrlint check examples/good.txt
```

## bad.txt

The same response as it usually ships: contradictory `Cache-Control`,
`Expires: 0`, an unquoted ETag, a cookie without `Secure`, a versioned
`Server` banner. Twelve findings across all three categories:

```bash
hdrlint check examples/bad.txt
hdrlint check --format json examples/bad.txt
```

## redirect-chain.txt

A `curl -siL`-style capture: a 301 followed by the final 200 (note the
lowercase HTTP/2 header names — case is irrelevant everywhere). hdrlint
lints every response in the chain separately:

```bash
hdrlint check examples/redirect-chain.txt
```

## capture.har

A two-entry HAR archive, as saved from browser devtools or a proxy. The
first entry is HTTPS (and commits the forbidden wildcard-plus-credentials
CORS combination); the second was served over plain HTTP, so hdrlint
flags its Strict-Transport-Security as ignored instead of demanding one:

```bash
hdrlint check examples/capture.har
```

## ci-gate.sh

The CI recipe: exit codes gate the build, `--format github` annotates the
PR, `--fail-on never` gives a report-only adoption mode:

```bash
bash examples/ci-gate.sh
```
