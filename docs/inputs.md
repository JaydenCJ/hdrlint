# Capture formats

hdrlint never talks to a network. It lints captures you already have —
which is the point: the same command works in CI, on an air-gapped
machine, and against staging environments that a SaaS scanner could never
reach. Two formats are accepted, sniffed automatically.

## Raw header dumps

Anything that looks like HTTP/1.x wire format:

```bash
curl -sD - -o /dev/null https://example.test/ > headers.txt   # headers only
curl -si  https://example.test/ > response.txt                # with body
curl -siL https://example.test/ > chain.txt                   # redirect chain
hdrlint check headers.txt response.txt chain.txt
```

Parsing rules:

- A response starts at a status line (`HTTP/1.1 200 OK`, `HTTP/2 200`).
- Header lines follow until the first blank line; anything after it is
  treated as body and skipped until the next status line, so `curl -i`
  output with bodies and full `-L` redirect chains both work. Every
  response in a chain is linted separately.
- Obsolete line folding (a continuation line starting with whitespace) is
  unfolded, remembered, and reported by the `obs-fold` rule. Lines with
  no colon are kept and reported by `field-name-invalid`. Malformed input
  reaches the rule engine instead of crashing the parser — linting broken
  headers is the job.
- A capture whose first line is `Name: value` instead of a status line
  (a devtools copy-paste) becomes a single headers-only response; rules
  that need the status code skip it.

Raw captures carry no URL, so hdrlint assumes HTTPS — that is what
production traffic is. Pass `--http` for a plain-HTTP capture: HTTPS-only
rules go quiet and `hsts-over-http` wakes up.

## HAR archives

Files ending in `.har` — or any input whose first byte is `{` — are
parsed as HAR 1.2, the export format of every browser devtools "Save all
as HAR" and most proxies:

```bash
hdrlint check session.har
```

Every completed entry is linted as one response, labelled with its
request URL. Entries with status 0 (aborted or blocked requests) carry no
server headers and are skipped. Because HAR entries know their URL, the
HTTPS/HTTP decision is made per entry — no flag needed.

## Reading from stdin

`-` reads a raw dump or HAR from stdin, so captures can be piped straight
out of other tooling:

```bash
curl -sD - -o /dev/null https://staging.example.test/ | hdrlint check -
```

Note that piping `curl` output means curl *does* touch the network —
hdrlint itself still reads only the bytes it is given.
