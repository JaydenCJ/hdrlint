// Behavior tests for the security rule set. Each test isolates one rule
// via lintOne and exercises both the firing and the passing shape.
package rules

import (
	"strings"
	"testing"
)

func TestHSTSPresence(t *testing.T) {
	if msgs := lintOne(t, "hsts-missing", https(mkResp(200))); len(msgs) != 1 {
		t.Fatalf("absent HSTS on HTTPS: %v", msgs)
	}
	ok := https(mkResp(200, "Strict-Transport-Security", "max-age=31536000"))
	if msgs := lintOne(t, "hsts-missing", ok); len(msgs) != 0 {
		t.Fatalf("present HSTS flagged: %v", msgs)
	}
	// Plain-HTTP capture: the rule is HTTPS-only and must not fire.
	if msgs := lintOne(t, "hsts-missing", &Target{Resp: mkResp(200), HTTPS: false}); len(msgs) != 0 {
		t.Fatalf("HSTS demanded over plain HTTP: %v", msgs)
	}
	// Conversely, sending STS over plain HTTP is itself a finding.
	sent := &Target{Resp: mkResp(200, "Strict-Transport-Security", "max-age=31536000"), HTTPS: false}
	if msgs := lintOne(t, "hsts-over-http", sent); len(msgs) != 1 {
		t.Fatalf("STS over plain HTTP not flagged: %v", msgs)
	}
}

func TestHSTSValue(t *testing.T) {
	cases := map[string]int{
		"max-age=31536000; includeSubDomains; preload": 0,
		`max-age="31536000"`:                           0, // quoted delta-seconds is grammatical
		"includeSubDomains":                            1, // required max-age missing
		"max-age":                                      1, // no value
		"max-age=ten":                                  1, // not delta-seconds
		"max-age=-1":                                   1, // negative
		"max @ge=1":                                    2, // bad token AND missing max-age
	}
	for value, want := range cases {
		msgs := lintOne(t, "hsts-malformed", https(mkResp(200, "Strict-Transport-Security", value)))
		if len(msgs) != want {
			t.Errorf("HSTS %q: got %d findings (%v), want %d", value, len(msgs), msgs, want)
		}
	}
	// A grammatical but short-lived policy is a separate, softer finding.
	short := https(mkResp(200, "Strict-Transport-Security", "max-age=86400"))
	msgs := lintOne(t, "hsts-short-max-age", short)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "86400") {
		t.Fatalf("one-day policy: %v", msgs)
	}
	long := https(mkResp(200, "Strict-Transport-Security", "max-age=15552000"))
	if msgs := lintOne(t, "hsts-short-max-age", long); len(msgs) != 0 {
		t.Fatalf("180-day policy flagged: %v", msgs)
	}
	// Unparseable max-age belongs to hsts-malformed, not this rule.
	bad := https(mkResp(200, "Strict-Transport-Security", "max-age=soon"))
	if msgs := lintOne(t, "hsts-short-max-age", bad); len(msgs) != 0 {
		t.Fatalf("malformed max-age double-reported: %v", msgs)
	}
}

func TestNosniff(t *testing.T) {
	if msgs := lintOne(t, "nosniff-missing", https(mkResp(200))); len(msgs) != 1 {
		t.Fatalf("missing nosniff: %v", msgs)
	}
	// 204 and 304 have no body to sniff.
	if msgs := lintOne(t, "nosniff-missing", https(mkResp(204))); len(msgs) != 0 {
		t.Fatalf("nosniff demanded on 204: %v", msgs)
	}
	ok := https(mkResp(200, "X-Content-Type-Options", "NoSniff")) // value is case-insensitive
	if msgs := lintOne(t, "nosniff-invalid", ok); len(msgs) != 0 {
		t.Fatalf("case-insensitive nosniff flagged: %v", msgs)
	}
	bad := https(mkResp(200, "X-Content-Type-Options", "none"))
	if msgs := lintOne(t, "nosniff-invalid", bad); len(msgs) != 1 {
		t.Fatalf("wrong nosniff value: %v", msgs)
	}
}

func TestFrameProtection(t *testing.T) {
	html := func(extra ...string) *Target {
		return https(mkResp(200, append([]string{"Content-Type", "text/html"}, extra...)...))
	}
	if msgs := lintOne(t, "frame-protection-missing", html()); len(msgs) != 1 {
		t.Fatalf("unprotected HTML: %v", msgs)
	}
	if msgs := lintOne(t, "frame-protection-missing", html("X-Frame-Options", "DENY")); len(msgs) != 0 {
		t.Fatalf("XFO not accepted: %v", msgs)
	}
	withCSP := html("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	if msgs := lintOne(t, "frame-protection-missing", withCSP); len(msgs) != 0 {
		t.Fatalf("CSP frame-ancestors not accepted: %v", msgs)
	}
	// JSON APIs cannot be framed meaningfully; the rule is HTML-gated.
	api := https(mkResp(200, "Content-Type", "application/json"))
	if msgs := lintOne(t, "frame-protection-missing", api); len(msgs) != 0 {
		t.Fatalf("non-HTML flagged: %v", msgs)
	}
}

func TestXFOInvalid(t *testing.T) {
	for _, ok := range []string{"DENY", "deny", "SAMEORIGIN", " sameorigin "} {
		if msgs := lintOne(t, "xfo-invalid", https(mkResp(200, "X-Frame-Options", ok))); len(msgs) != 0 {
			t.Errorf("valid XFO %q flagged: %v", ok, msgs)
		}
	}
	obsolete := lintOne(t, "xfo-invalid", https(mkResp(200, "X-Frame-Options", "ALLOW-FROM https://example.test")))
	if len(obsolete) != 1 || !strings.Contains(obsolete[0], "ALLOW-FROM") {
		t.Fatalf("ALLOW-FROM: %v", obsolete)
	}
	if msgs := lintOne(t, "xfo-invalid", https(mkResp(200, "X-Frame-Options", "ALLOWALL"))); len(msgs) != 1 {
		t.Fatalf("garbage XFO: %v", msgs)
	}
}

func TestCSPMissing(t *testing.T) {
	html := https(mkResp(200, "Content-Type", "text/html; charset=utf-8"))
	if msgs := lintOne(t, "csp-missing", html); len(msgs) != 1 {
		t.Fatalf("HTML without CSP: %v", msgs)
	}
	reportOnly := https(mkResp(200,
		"Content-Type", "text/html",
		"Content-Security-Policy-Report-Only", "default-src 'self'"))
	msgs := lintOne(t, "csp-missing", reportOnly)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "report-only") {
		t.Fatalf("report-only should still count as missing enforcement: %v", msgs)
	}
	enforcing := https(mkResp(200,
		"Content-Type", "text/html",
		"Content-Security-Policy", "default-src 'self'"))
	if msgs := lintOne(t, "csp-missing", enforcing); len(msgs) != 0 {
		t.Fatalf("enforcing CSP flagged: %v", msgs)
	}
}

func TestCSPScriptPolicy(t *testing.T) {
	mk := func(policy string) *Target {
		return https(mkResp(200, "Content-Type", "text/html", "Content-Security-Policy", policy))
	}
	if msgs := lintOne(t, "csp-unsafe-inline", mk("script-src 'self' 'unsafe-inline'")); len(msgs) != 1 {
		t.Fatalf("bare unsafe-inline: %v", msgs)
	}
	// default-src governs scripts when script-src is absent.
	if msgs := lintOne(t, "csp-unsafe-inline", mk("default-src 'unsafe-inline'")); len(msgs) != 1 {
		t.Fatalf("unsafe-inline via default-src: %v", msgs)
	}
	// A nonce or hash makes browsers ignore 'unsafe-inline' (kept only
	// as a fallback for pre-CSP2 browsers), so the policy is still strict.
	nonce := mk("script-src 'self' 'unsafe-inline' 'nonce-abc123'")
	if msgs := lintOne(t, "csp-unsafe-inline", nonce); len(msgs) != 0 {
		t.Fatalf("nonce fallback pattern flagged: %v", msgs)
	}
	strict := mk("script-src 'unsafe-inline' 'strict-dynamic' 'sha256-xyz'")
	if msgs := lintOne(t, "csp-unsafe-inline", strict); len(msgs) != 0 {
		t.Fatalf("strict-dynamic pattern flagged: %v", msgs)
	}
	// Wildcard script sources are the other way to void the policy.
	if msgs := lintOne(t, "csp-wildcard-script", mk("script-src *")); len(msgs) != 1 {
		t.Fatalf("wildcard script-src: %v", msgs)
	}
	if msgs := lintOne(t, "csp-wildcard-script", mk("default-src *; img-src 'self'")); len(msgs) != 1 {
		t.Fatalf("wildcard default-src: %v", msgs)
	}
	// A wildcard in img-src only is not a script wildcard.
	if msgs := lintOne(t, "csp-wildcard-script", mk("script-src 'self'; img-src *")); len(msgs) != 0 {
		t.Fatalf("img-src wildcard flagged as script: %v", msgs)
	}
}

func TestCookieAttributeRules(t *testing.T) {
	insecure := https(mkResp(200, "Set-Cookie", "session=abc; Path=/; HttpOnly"))
	msgs := lintOne(t, "cookie-no-secure", insecure)
	if len(msgs) != 1 || !strings.Contains(msgs[0], `"session"`) {
		t.Fatalf("missing Secure: %v", msgs)
	}
	ok := https(mkResp(200, "Set-Cookie", "session=abc; Secure; HttpOnly"))
	if msgs := lintOne(t, "cookie-no-secure", ok); len(msgs) != 0 {
		t.Fatalf("Secure cookie flagged: %v", msgs)
	}
	// Two cookies, one bad → exactly one finding, naming the right cookie.
	two := https(mkResp(200,
		"Set-Cookie", "good=1; Secure",
		"Set-Cookie", "bad=2; Path=/"))
	msgs = lintOne(t, "cookie-no-secure", two)
	if len(msgs) != 1 || !strings.Contains(msgs[0], `"bad"`) {
		t.Fatalf("per-cookie reporting: %v", msgs)
	}
	// HttpOnly and SameSite are independent warnings.
	c := https(mkResp(200, "Set-Cookie", "session=abc; Secure"))
	if msgs := lintOne(t, "cookie-no-httponly", c); len(msgs) != 1 {
		t.Fatalf("missing HttpOnly: %v", msgs)
	}
	if msgs := lintOne(t, "cookie-no-samesite", c); len(msgs) != 1 {
		t.Fatalf("missing SameSite: %v", msgs)
	}
	full := https(mkResp(200, "Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax"))
	if msgs := lintOne(t, "cookie-no-httponly", full); len(msgs) != 0 {
		t.Fatalf("HttpOnly present but flagged: %v", msgs)
	}
	if msgs := lintOne(t, "cookie-no-samesite", full); len(msgs) != 0 {
		t.Fatalf("SameSite present but flagged: %v", msgs)
	}
	// SameSite=None additionally demands Secure.
	bad := https(mkResp(200, "Set-Cookie", "track=1; SameSite=None"))
	if msgs := lintOne(t, "cookie-samesite-none-insecure", bad); len(msgs) != 1 {
		t.Fatalf("SameSite=None without Secure: %v", msgs)
	}
	secureNone := https(mkResp(200, "Set-Cookie", "track=1; SameSite=none; Secure"))
	if msgs := lintOne(t, "cookie-samesite-none-insecure", secureNone); len(msgs) != 0 {
		t.Fatalf("valid SameSite=None flagged: %v", msgs)
	}
	laxCookie := https(mkResp(200, "Set-Cookie", "track=1; SameSite=Lax"))
	if msgs := lintOne(t, "cookie-samesite-none-insecure", laxCookie); len(msgs) != 0 {
		t.Fatalf("SameSite=Lax flagged: %v", msgs)
	}
}

func TestCORSWildcardCredentials(t *testing.T) {
	bad := https(mkResp(200,
		"Access-Control-Allow-Origin", "*",
		"Access-Control-Allow-Credentials", "true"))
	if msgs := lintOne(t, "cors-wildcard-credentials", bad); len(msgs) != 1 {
		t.Fatalf("wildcard + credentials: %v", msgs)
	}
	// Wildcard without credentials is a legitimate public-API shape.
	public := https(mkResp(200, "Access-Control-Allow-Origin", "*"))
	if msgs := lintOne(t, "cors-wildcard-credentials", public); len(msgs) != 0 {
		t.Fatalf("public CORS flagged: %v", msgs)
	}
	pinned := https(mkResp(200,
		"Access-Control-Allow-Origin", "https://app.example.test",
		"Access-Control-Allow-Credentials", "true"))
	if msgs := lintOne(t, "cors-wildcard-credentials", pinned); len(msgs) != 0 {
		t.Fatalf("pinned origin flagged: %v", msgs)
	}
}

func TestDisclosureHeaders(t *testing.T) {
	verbose := https(mkResp(200, "Server", "Apache/2.4.62 (Ubuntu)"))
	if msgs := lintOne(t, "server-version", verbose); len(msgs) != 1 {
		t.Fatalf("versioned Server: %v", msgs)
	}
	terse := https(mkResp(200, "Server", "nginx"))
	if msgs := lintOne(t, "server-version", terse); len(msgs) != 0 {
		t.Fatalf("bare product name flagged: %v", msgs)
	}
	xpb := https(mkResp(200, "X-Powered-By", "PHP/8.3.8"))
	if msgs := lintOne(t, "x-powered-by", xpb); len(msgs) != 1 {
		t.Fatalf("X-Powered-By: %v", msgs)
	}
	legacy := https(mkResp(200, "X-XSS-Protection", "1; mode=block"))
	if msgs := lintOne(t, "xss-protection-legacy", legacy); len(msgs) != 1 {
		t.Fatalf("legacy auditor: %v", msgs)
	}
	// "0" is the one safe value: it disables the auditor everywhere.
	zero := https(mkResp(200, "X-XSS-Protection", "0"))
	if msgs := lintOne(t, "xss-protection-legacy", zero); len(msgs) != 0 {
		t.Fatalf("X-XSS-Protection: 0 flagged: %v", msgs)
	}
}

func TestReferrerPolicyMissing(t *testing.T) {
	html := https(mkResp(200, "Content-Type", "text/html"))
	if msgs := lintOne(t, "referrer-policy-missing", html); len(msgs) != 1 {
		t.Fatalf("HTML without Referrer-Policy: %v", msgs)
	}
	api := https(mkResp(200, "Content-Type", "application/json"))
	if msgs := lintOne(t, "referrer-policy-missing", api); len(msgs) != 0 {
		t.Fatalf("non-HTML flagged: %v", msgs)
	}
}
