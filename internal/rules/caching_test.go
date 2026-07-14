// Behavior tests for the caching rule set.
package rules

import (
	"strings"
	"testing"
)

func TestCacheControlPresenceAndGrammar(t *testing.T) {
	if msgs := lintOne(t, "cache-control-missing", https(mkResp(200))); len(msgs) != 1 {
		t.Fatalf("200 without Cache-Control: %v", msgs)
	}
	// Only 200 is heuristically cacheable enough to demand a policy;
	// errors and headers-only captures (status 0) are exempt.
	if msgs := lintOne(t, "cache-control-missing", https(mkResp(404))); len(msgs) != 0 {
		t.Fatalf("404 flagged: %v", msgs)
	}
	if msgs := lintOne(t, "cache-control-missing", https(mkResp(0))); len(msgs) != 0 {
		t.Fatalf("headers-only capture flagged: %v", msgs)
	}
	ok := https(mkResp(200, "Cache-Control", "no-store"))
	if msgs := lintOne(t, "cache-control-missing", ok); len(msgs) != 0 {
		t.Fatalf("explicit policy flagged: %v", msgs)
	}
	// Grammar-level problems are a separate warning.
	dup := https(mkResp(200, "Cache-Control", "max-age=60,,no-cache"))
	if msgs := lintOne(t, "cache-control-malformed", dup); len(msgs) != 1 {
		t.Fatalf("empty list element: %v", msgs)
	}
	quoted := https(mkResp(200, "Cache-Control", `max-age="600"`))
	msgs := lintOne(t, "cache-control-malformed", quoted)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "quoted-string") {
		t.Fatalf("quoted delta-seconds: %v", msgs)
	}
	clean := https(mkResp(200, "Cache-Control", "public, max-age=600"))
	if msgs := lintOne(t, "cache-control-malformed", clean); len(msgs) != 0 {
		t.Fatalf("clean policy flagged: %v", msgs)
	}
}

func TestCacheControlConflicts(t *testing.T) {
	bad := https(mkResp(200, "Cache-Control", "no-store, max-age=600, public"))
	msgs := lintOne(t, "cache-no-store-conflict", bad)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "max-age, public") {
		t.Fatalf("conflict list: %v", msgs)
	}
	// no-store with only reuse-constraining directives is fine.
	belt := https(mkResp(200, "Cache-Control", "no-store, no-cache, must-revalidate"))
	if msgs := lintOne(t, "cache-no-store-conflict", belt); len(msgs) != 0 {
		t.Fatalf("no-store boilerplate flagged: %v", msgs)
	}
	// The conflict is also caught across two Cache-Control field lines,
	// since recipients combine them into one list.
	split := https(mkResp(200, "Cache-Control", "no-store", "Cache-Control", "max-age=600"))
	if msgs := lintOne(t, "cache-no-store-conflict", split); len(msgs) != 1 {
		t.Fatalf("split-header conflict missed: %v", msgs)
	}
	// public and private are mutually exclusive.
	pubPriv := https(mkResp(200, "Cache-Control", "public, private, max-age=60"))
	if msgs := lintOne(t, "cache-public-private", pubPriv); len(msgs) != 1 {
		t.Fatalf("public+private: %v", msgs)
	}
	privOnly := https(mkResp(200, "Cache-Control", "private, max-age=60"))
	if msgs := lintOne(t, "cache-public-private", privOnly); len(msgs) != 0 {
		t.Fatalf("private alone flagged: %v", msgs)
	}
	// private makes s-maxage dead weight.
	odd := https(mkResp(200, "Cache-Control", "private, s-maxage=600"))
	if msgs := lintOne(t, "cache-private-smaxage", odd); len(msgs) != 1 {
		t.Fatalf("private+s-maxage: %v", msgs)
	}
	cdn := https(mkResp(200, "Cache-Control", "public, s-maxage=600, max-age=60"))
	if msgs := lintOne(t, "cache-private-smaxage", cdn); len(msgs) != 0 {
		t.Fatalf("valid CDN policy flagged: %v", msgs)
	}
}

func TestInvalidMaxAge(t *testing.T) {
	cases := map[string]int{
		"max-age=600":              0,
		"max-age=0":                0,
		"max-age=-1":               1, // negative
		"max-age=1.5":              1, // float
		"max-age=600s":             1, // units
		"max-age":                  1, // missing argument entirely
		"s-maxage=never":           1,
		"max-age=abc, s-maxage=-2": 2, // both reported independently
	}
	for value, want := range cases {
		msgs := lintOne(t, "cache-invalid-max-age", https(mkResp(200, "Cache-Control", value)))
		if len(msgs) != want {
			t.Errorf("Cache-Control %q: got %d findings (%v), want %d", value, len(msgs), msgs, want)
		}
	}
}

func TestUnknownDirective(t *testing.T) {
	typo := https(mkResp(200, "Cache-Control", "no-chache, max-age=60"))
	msgs := lintOne(t, "cache-unknown-directive", typo)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "no-chache") {
		t.Fatalf("typo directive: %v", msgs)
	}
	reqOnly := https(mkResp(200, "Cache-Control", "only-if-cached"))
	msgs = lintOne(t, "cache-unknown-directive", reqOnly)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "request directive") {
		t.Fatalf("request-only directive: %v", msgs)
	}
	// The full legitimate vocabulary must pass, including RFC 5861 and
	// RFC 8246 extensions.
	known := https(mkResp(200, "Cache-Control",
		"public, max-age=600, s-maxage=3600, immutable, stale-while-revalidate=30, stale-if-error=300, must-understand, no-transform"))
	if msgs := lintOne(t, "cache-unknown-directive", known); len(msgs) != 0 {
		t.Fatalf("known directives flagged: %v", msgs)
	}
}

func TestExpires(t *testing.T) {
	zero := https(mkResp(200, "Expires", "0"))
	if msgs := lintOne(t, "expires-invalid", zero); len(msgs) != 1 {
		t.Fatalf("Expires: 0: %v", msgs)
	}
	iso := https(mkResp(200, "Expires", "2026-07-11T12:00:00Z"))
	if msgs := lintOne(t, "expires-invalid", iso); len(msgs) != 1 {
		t.Fatalf("ISO 8601 Expires: %v", msgs)
	}
	ok := https(mkResp(200, "Expires", "Sat, 11 Jul 2026 12:00:00 GMT"))
	if msgs := lintOne(t, "expires-invalid", ok); len(msgs) != 0 {
		t.Fatalf("valid Expires flagged: %v", msgs)
	}
	// A valid Expires can still be dead weight next to max-age.
	both := https(mkResp(200,
		"Cache-Control", "max-age=600",
		"Expires", "Sat, 11 Jul 2026 12:00:00 GMT"))
	if msgs := lintOne(t, "expires-ignored", both); len(msgs) != 1 {
		t.Fatalf("Expires alongside max-age: %v", msgs)
	}
	// Expires with no competing lifetime is the legitimate HTTP/1.0
	// compatibility play.
	solo := https(mkResp(200, "Expires", "Sat, 11 Jul 2026 12:00:00 GMT", "Cache-Control", "public"))
	if msgs := lintOne(t, "expires-ignored", solo); len(msgs) != 0 {
		t.Fatalf("harmless Expires flagged: %v", msgs)
	}
}

func TestPragmaAndAge(t *testing.T) {
	p := https(mkResp(200, "Pragma", "no-cache"))
	if msgs := lintOne(t, "pragma-response", p); len(msgs) != 1 {
		t.Fatalf("response Pragma: %v", msgs)
	}
	bad := https(mkResp(200, "Age", "-30"))
	if msgs := lintOne(t, "age-invalid", bad); len(msgs) != 1 {
		t.Fatalf("negative Age: %v", msgs)
	}
	ok := https(mkResp(200, "Age", "120"))
	if msgs := lintOne(t, "age-invalid", ok); len(msgs) != 0 {
		t.Fatalf("valid Age flagged: %v", msgs)
	}
}

func TestVaryWildcard(t *testing.T) {
	star := https(mkResp(200, "Vary", "*"))
	if msgs := lintOne(t, "vary-wildcard", star); len(msgs) != 1 {
		t.Fatalf("Vary: *: %v", msgs)
	}
	mixed := https(mkResp(200, "Vary", "Accept-Encoding, *"))
	msgs := lintOne(t, "vary-wildcard", mixed)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "moot") {
		t.Fatalf("mixed Vary: %v", msgs)
	}
	// Wildcard hides in a second Vary line: list-based fields combine.
	split := https(mkResp(200, "Vary", "Accept-Encoding", "Vary", "*"))
	if msgs := lintOne(t, "vary-wildcard", split); len(msgs) != 1 {
		t.Fatalf("split Vary wildcard missed: %v", msgs)
	}
	normal := https(mkResp(200, "Vary", "Accept-Encoding, Accept-Language"))
	if msgs := lintOne(t, "vary-wildcard", normal); len(msgs) != 0 {
		t.Fatalf("normal Vary flagged: %v", msgs)
	}
}

func TestETagMalformed(t *testing.T) {
	// The classic bug: frameworks emitting the hash without quotes.
	bare := https(mkResp(200, "ETag", "33a64df551425fcc"))
	if msgs := lintOne(t, "etag-malformed", bare); len(msgs) != 1 {
		t.Fatalf("unquoted ETag: %v", msgs)
	}
	for _, ok := range []string{`"33a64df5"`, `W/"weak-tag"`, `""`} {
		if msgs := lintOne(t, "etag-malformed", https(mkResp(200, "ETag", ok))); len(msgs) != 0 {
			t.Errorf("valid ETag %s flagged: %v", ok, msgs)
		}
	}
}

func TestLastModifiedFuture(t *testing.T) {
	future := https(mkResp(200,
		"Date", "Sat, 11 Jul 2026 12:00:00 GMT",
		"Last-Modified", "Sun, 12 Jul 2026 09:00:00 GMT"))
	if msgs := lintOne(t, "last-modified-future", future); len(msgs) != 1 {
		t.Fatalf("future Last-Modified: %v", msgs)
	}
	past := https(mkResp(200,
		"Date", "Sat, 11 Jul 2026 12:00:00 GMT",
		"Last-Modified", "Fri, 10 Jul 2026 08:00:00 GMT"))
	if msgs := lintOne(t, "last-modified-future", past); len(msgs) != 0 {
		t.Fatalf("valid Last-Modified flagged: %v", msgs)
	}
	// No wall clock is consulted: without a Date header there is no
	// deterministic reference point, so the rule stays silent.
	noDate := https(mkResp(200, "Last-Modified", "Sun, 12 Jul 2026 09:00:00 GMT"))
	if msgs := lintOne(t, "last-modified-future", noDate); len(msgs) != 0 {
		t.Fatalf("rule fired without a Date reference: %v", msgs)
	}
}
