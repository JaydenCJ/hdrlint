// In-process CLI integration tests: Run(argv) against fixture captures in
// temp dirs, asserting on output and exit codes. No binary, no network.
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cleanCapture is a fully hardened response that triggers zero rules.
const cleanCapture = `HTTP/1.1 200 OK
Date: Sat, 11 Jul 2026 12:00:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1234
Cache-Control: private, no-cache
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
ETag: "v42"
Server: nginx

`

// badCapture triggers findings at every severity.
const badCapture = `HTTP/1.1 200 OK
Date: Sat, 11 Jul 2026 12:00:00 GMT
Content-Type: text/html
Cache-Control: no-store, max-age=600
ETag: 33a64df551425fcc
Server: Apache/2.4.62 (Ubuntu)

`

// warnOnlyCapture triggers warnings and notices but no errors.
const warnOnlyCapture = `HTTP/1.1 200 OK
Date: Sat, 11 Jul 2026 12:00:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 42
Cache-Control: private, no-cache
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
Referrer-Policy: no-referrer

`

// run invokes the CLI in-process and captures both streams.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// writeCapture drops content into a temp file and returns its path.
func writeCapture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestVersionHelpUsage(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		code, out, _ := run(t, arg)
		if code != ExitOK || out != "hdrlint 0.1.0\n" {
			t.Errorf("%s: code=%d out=%q", arg, code, out)
		}
	}
	code, out, _ := run(t, "help")
	if code != ExitOK || !strings.Contains(out, "hdrlint check") {
		t.Fatalf("help: code=%d", code)
	}
	// No arguments is a usage error: hdrlint never reads implicit input.
	code, _, errOut := run(t)
	if code != ExitUsage || !strings.Contains(errOut, "usage") {
		t.Fatalf("no args: code=%d stderr=%q", code, errOut)
	}
	code, _, _ = run(t, "--bogus")
	if code != ExitUsage {
		t.Fatalf("unknown flag: code=%d, want %d", code, ExitUsage)
	}
}

func TestCheckFindsProblemsAndExitsOne(t *testing.T) {
	path := writeCapture(t, "bad.txt", badCapture)
	code, out, _ := run(t, "check", path)
	if code != ExitFindings {
		t.Fatalf("exit=%d, want %d", code, ExitFindings)
	}
	for _, want := range []string{
		"HTTP/1.1 200 OK",
		"cache-no-store-conflict",
		"etag-malformed",
		"[RFC 9111 §5.2.2.5]", // the citation is the product
		"[RFC 9110 §8.8.3]",
		"server-version",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
}

func TestCheckCleanCaptureExitsZero(t *testing.T) {
	path := writeCapture(t, "clean.txt", cleanCapture)
	code, out, errOut := run(t, "check", path)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%q\n---\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "ok — no findings") {
		t.Fatalf("clean report:\n%s", out)
	}
	// A bare path with no subcommand defaults to check.
	code, out, _ = run(t, path)
	if code != ExitOK || !strings.Contains(out, "ok — no findings") {
		t.Fatalf("bare path: code=%d\n%s", code, out)
	}
}

func TestCheckFailOnThresholds(t *testing.T) {
	path := writeCapture(t, "warns.txt", warnOnlyCapture)
	// Default --fail-on error: warnings alone do not fail the build.
	if code, _, _ := run(t, "check", path); code != ExitOK {
		t.Fatal("warnings failed the run at default threshold")
	}
	if code, _, _ := run(t, "check", "--fail-on", "warn", path); code != ExitFindings {
		t.Fatal("--fail-on warn did not fail on warnings")
	}
	if code, _, _ := run(t, "check", "--fail-on", "info", path); code != ExitFindings {
		t.Fatal("--fail-on info did not fail on notices")
	}
	bad := writeCapture(t, "bad.txt", badCapture)
	if code, _, _ := run(t, "check", "--fail-on", "never", bad); code != ExitOK {
		t.Fatal("--fail-on never still failed (report-only mode broken)")
	}
	if code, _, _ := run(t, "check", "--fail-on", "fatal", bad); code != ExitUsage {
		t.Fatal("bad --fail-on value accepted")
	}
}

func TestCheckDisableAndOnly(t *testing.T) {
	path := writeCapture(t, "bad.txt", badCapture)
	code, out, _ := run(t, "check",
		"--disable", "cache-no-store-conflict",
		"--disable", "etag-malformed",
		path)
	if strings.Contains(out, "etag-malformed") || strings.Contains(out, "cache-no-store-conflict") {
		t.Fatalf("disabled rules still reported:\n%s", out)
	}
	if code != ExitOK {
		t.Fatalf("with both errors disabled, exit=%d, want 0", code)
	}
	_, out, _ = run(t, "check", "--only", "etag-malformed", path)
	if !strings.Contains(out, "etag-malformed") || strings.Contains(out, "hsts-missing") {
		t.Fatalf("--only did not isolate the rule:\n%s", out)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	path := writeCapture(t, "bad.txt", badCapture)
	// A typo in --disable/--only must fail loudly, not silently pass CI.
	code, _, errOut := run(t, "check", "--disable", "no-such-rule", path)
	if code != ExitUsage || !strings.Contains(errOut, "no-such-rule") {
		t.Fatalf("unknown rule id: code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := run(t, "check", "--format", "yaml", path); code != ExitUsage {
		t.Error("bad --format accepted")
	}
	if code, _, errOut := run(t, "check"); code != ExitUsage || !strings.Contains(errOut, "no input") {
		t.Error("check without inputs accepted")
	}
}

func TestCheckRuntimeErrors(t *testing.T) {
	if code, _, _ := run(t, "check", filepath.Join(t.TempDir(), "absent.txt")); code != ExitRuntime {
		t.Error("missing file did not exit 3")
	}
	garbage := writeCapture(t, "garbage.txt", "this is not an HTTP capture\n")
	if code, _, errOut := run(t, "check", garbage); code != ExitRuntime || !strings.Contains(errOut, "garbage.txt") {
		t.Errorf("unparseable file: code=%d stderr=%q", code, errOut)
	}
}

func TestCheckReadsStdin(t *testing.T) {
	var stdout, stderr strings.Builder
	code := runCheck([]string{"-"}, &stdout, &stderr, strings.NewReader(badCapture))
	if code != ExitFindings {
		t.Fatalf("stdin: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stdin#1") {
		t.Fatalf("stdin label missing:\n%s", stdout.String())
	}
}

func TestCheckOutputFormats(t *testing.T) {
	path := writeCapture(t, "bad.txt", badCapture)
	_, out, _ := run(t, "check", "--format", "json", path)
	var env struct {
		Tool      string `json:"tool"`
		Responses []struct {
			Findings []struct {
				Rule     string `json:"rule"`
				Citation struct {
					URL string `json:"url"`
				} `json:"citation"`
			} `json:"findings"`
		} `json:"responses"`
		Summary struct {
			Errors int `json:"errors"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if env.Tool != "hdrlint" || env.Summary.Errors == 0 || len(env.Responses) != 1 {
		t.Fatalf("envelope: %+v", env)
	}
	for _, f := range env.Responses[0].Findings {
		if f.Citation.URL == "" {
			t.Errorf("finding %s has no citation URL", f.Rule)
		}
	}
	// github format: workflow-command annotations, same findings.
	code, out, _ := run(t, "check", "--format", "github", path)
	if code != ExitFindings {
		t.Fatalf("github format exit=%d", code)
	}
	if !strings.Contains(out, "::error title=hdrlint ") {
		t.Fatalf("github annotations missing:\n%s", out)
	}
}

func TestCheckMultipleFilesAndRedirectChain(t *testing.T) {
	chain := writeCapture(t, "chain.txt", strings.Join([]string{
		"HTTP/1.1 301 Moved Permanently",
		"Date: Sat, 11 Jul 2026 12:00:00 GMT",
		"", // no Location: redirect-location-missing must fire
		"HTTP/1.1 200 OK",
		"Date: Sat, 11 Jul 2026 12:00:00 GMT",
		"Content-Type: text/plain",
		"",
	}, "\n"))
	clean := writeCapture(t, "clean.txt", cleanCapture)
	_, out, _ := run(t, "check", "--only", "redirect-location-missing", chain, clean)
	if !strings.Contains(out, "chain.txt#1") || !strings.Contains(out, "chain.txt#2") || !strings.Contains(out, "clean.txt#1") {
		t.Fatalf("multi-file report:\n%s", out)
	}
	if !strings.Contains(out, "checked 3 responses") {
		t.Fatalf("summary should count 3 responses:\n%s", out)
	}
	if !strings.Contains(out, "redirect-location-missing") {
		t.Fatalf("301 without Location not flagged:\n%s", out)
	}
}

func TestCheckHARRespectsPerEntryScheme(t *testing.T) {
	har := writeCapture(t, "cap.har", `{
	  "log": {"entries": [
	    {"request": {"url": "https://example.test/a"},
	     "response": {"status": 200, "httpVersion": "http/2.0",
	       "headers": [{"name": "Content-Type", "value": "text/plain"}]}},
	    {"request": {"url": "http://example.test/b"},
	     "response": {"status": 200, "httpVersion": "HTTP/1.1",
	       "headers": [{"name": "Content-Type", "value": "text/plain"},
	                   {"name": "Strict-Transport-Security", "value": "max-age=31536000"}]}}
	  ]}
	}`)
	_, out, _ := run(t, "check", "--only", "hsts-missing", "--only", "hsts-over-http", har)
	// Entry A (https) lacks HSTS; entry B (http) sends HSTS uselessly.
	if !strings.Contains(out, "https://example.test/a") || !strings.Contains(out, "hsts-missing") {
		t.Fatalf("HTTPS entry not linted for HSTS:\n%s", out)
	}
	if !strings.Contains(out, "hsts-over-http") {
		t.Fatalf("HTTP entry's useless HSTS not flagged:\n%s", out)
	}
}

func TestCheckHTTPFlag(t *testing.T) {
	capture := writeCapture(t, "http.txt", "HTTP/1.1 200 OK\nSet-Cookie: id=1; Path=/\n\n")
	// Default (assumed HTTPS): cookie-no-secure fires.
	_, out, _ := run(t, "check", "--only", "cookie-no-secure", capture)
	if !strings.Contains(out, "cookie-no-secure") {
		t.Fatalf("HTTPS default not applied:\n%s", out)
	}
	// With --http the HTTPS-only rule is silenced.
	_, out, _ = run(t, "check", "--http", "--only", "cookie-no-secure", capture)
	if strings.Contains(out, "cookie-no-secure") {
		t.Fatalf("--http did not skip HTTPS-only rules:\n%s", out)
	}
}

func TestRulesSubcommand(t *testing.T) {
	code, out, _ := run(t, "rules")
	if code != ExitOK {
		t.Fatalf("rules: exit=%d", code)
	}
	for _, want := range []string{"security (", "caching (", "correctness (", "[RFC 9110 §5.3]"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules output missing %q", want)
		}
	}
	code, out, _ = run(t, "rules", "--format", "json")
	if code != ExitOK || !json.Valid([]byte(out)) {
		t.Fatalf("rules --format json: exit=%d valid=%v", code, json.Valid([]byte(out)))
	}
	code, out, _ = run(t, "rules", "--category", "caching")
	if code != ExitOK || strings.Contains(out, "hsts-missing") {
		t.Fatalf("category filter leaked other categories:\n%s", out)
	}
	if code, _, _ := run(t, "rules", "--category", "nonsense"); code != ExitUsage {
		t.Fatal("bad category accepted")
	}
}

func TestExplainSubcommand(t *testing.T) {
	code, out, _ := run(t, "explain", "content-length-transfer-encoding")
	if code != ExitOK {
		t.Fatalf("explain: exit=%d", code)
	}
	for _, want := range []string{"correctness", "error", "RFC 9112 §6.3", "smuggling"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q\n---\n%s", want, out)
		}
	}
	if code, _, _ := run(t, "explain", "no-such-rule"); code != ExitUsage {
		t.Fatal("unknown rule id accepted")
	}
	if code, _, _ := run(t, "explain"); code != ExitUsage {
		t.Fatal("missing argument accepted")
	}
}
