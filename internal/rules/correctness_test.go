// Behavior tests for the correctness (protocol conformance) rule set,
// plus the exemplary-response integration test proving a well-configured
// response yields zero findings.
package rules

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
)

func TestDuplicateSingleton(t *testing.T) {
	differing := https(mkResp(200,
		"Content-Type", "text/html",
		"Content-Type", "application/json"))
	msgs := lintOne(t, "duplicate-singleton", differing)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "differing") {
		t.Fatalf("differing duplicates: %v", msgs)
	}
	identical := https(mkResp(200, "Date", "Sat, 11 Jul 2026 12:00:00 GMT", "Date", "Sat, 11 Jul 2026 12:00:00 GMT"))
	msgs = lintOne(t, "duplicate-singleton", identical)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "identical") {
		t.Fatalf("identical duplicates: %v", msgs)
	}
	// Set-Cookie is the deliberate exception: multiple lines are its
	// normal shape and must never be flagged.
	cookies := https(mkResp(200, "Set-Cookie", "a=1", "Set-Cookie", "b=2"))
	if msgs := lintOne(t, "duplicate-singleton", cookies); len(msgs) != 0 {
		t.Fatalf("Set-Cookie flagged as duplicate: %v", msgs)
	}
}

func TestContentLengthTransferEncoding(t *testing.T) {
	smuggle := https(mkResp(200, "Content-Length", "42", "Transfer-Encoding", "chunked"))
	msgs := lintOne(t, "content-length-transfer-encoding", smuggle)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "smuggling") {
		t.Fatalf("CL+TE: %v", msgs)
	}
	chunkedOnly := https(mkResp(200, "Transfer-Encoding", "chunked"))
	if msgs := lintOne(t, "content-length-transfer-encoding", chunkedOnly); len(msgs) != 0 {
		t.Fatalf("TE alone flagged: %v", msgs)
	}
}

func TestContentLengthValueAndStatus(t *testing.T) {
	for _, bad := range []string{"-1", "4.5", "42, 42", "abc"} {
		msgs := lintOne(t, "content-length-invalid", https(mkResp(200, "Content-Length", bad)))
		if len(msgs) != 1 {
			t.Errorf("Content-Length %q: %v", bad, msgs)
		}
	}
	ok := https(mkResp(200, "Content-Length", "1234"))
	if msgs := lintOne(t, "content-length-invalid", ok); len(msgs) != 0 {
		t.Fatalf("valid Content-Length flagged: %v", msgs)
	}
	// Some statuses forbid Content-Length outright.
	on204 := https(mkResp(204, "Content-Length", "0"))
	if msgs := lintOne(t, "content-length-status", on204); len(msgs) != 1 {
		t.Fatalf("Content-Length on 204: %v", msgs)
	}
	on100 := https(mkResp(100, "Content-Length", "0"))
	if msgs := lintOne(t, "content-length-status", on100); len(msgs) != 1 {
		t.Fatalf("Content-Length on 100: %v", msgs)
	}
	// 304 may carry the Content-Length the 200 would have had.
	on304 := https(mkResp(304, "Content-Length", "1234"))
	if msgs := lintOne(t, "content-length-status", on304); len(msgs) != 0 {
		t.Fatalf("Content-Length on 304 flagged: %v", msgs)
	}
}

func TestContentTypeRules(t *testing.T) {
	if msgs := lintOne(t, "content-type-missing", https(mkResp(200))); len(msgs) != 1 {
		t.Fatalf("200 without Content-Type: %v", msgs)
	}
	// Bodyless statuses, explicit empty bodies, and headers-only
	// captures don't need a type.
	for _, target := range []*Target{
		https(mkResp(204)),
		https(mkResp(304)),
		https(mkResp(200, "Content-Length", "0")),
		https(mkResp(0)),
	} {
		if msgs := lintOne(t, "content-type-missing", target); len(msgs) != 0 {
			t.Errorf("status %d flagged: %v", target.Resp.StatusCode, msgs)
		}
	}
	// A present Content-Type must still parse as a media type.
	bad := https(mkResp(200, "Content-Type", "texthtml"))
	if msgs := lintOne(t, "content-type-malformed", bad); len(msgs) != 1 {
		t.Fatalf("slash-less media type: %v", msgs)
	}
	ok := https(mkResp(200, "Content-Type", "application/json; charset=utf-8"))
	if msgs := lintOne(t, "content-type-malformed", ok); len(msgs) != 0 {
		t.Fatalf("valid media type flagged: %v", msgs)
	}
	// text/html specifically should declare its charset.
	html := https(mkResp(200, "Content-Type", "text/html"))
	if msgs := lintOne(t, "charset-missing", html); len(msgs) != 1 {
		t.Fatalf("text/html without charset: %v", msgs)
	}
	declared := https(mkResp(200, "Content-Type", "text/html; charset=utf-8"))
	if msgs := lintOne(t, "charset-missing", declared); len(msgs) != 0 {
		t.Fatalf("declared charset flagged: %v", msgs)
	}
	// JSON is UTF-8 by definition; no charset needed.
	json := https(mkResp(200, "Content-Type", "application/json"))
	if msgs := lintOne(t, "charset-missing", json); len(msgs) != 0 {
		t.Fatalf("application/json flagged: %v", msgs)
	}
}

func TestDateMissing(t *testing.T) {
	if msgs := lintOne(t, "date-missing", https(mkResp(200))); len(msgs) != 1 {
		t.Fatalf("200 without Date: %v", msgs)
	}
	// 5xx responses are exempt: the origin may have no working clock.
	if msgs := lintOne(t, "date-missing", https(mkResp(500))); len(msgs) != 0 {
		t.Fatalf("500 flagged: %v", msgs)
	}
	if msgs := lintOne(t, "date-missing", https(mkResp(0))); len(msgs) != 0 {
		t.Fatalf("headers-only capture flagged: %v", msgs)
	}
}

func TestDateFormats(t *testing.T) {
	iso := https(mkResp(200, "Date", "2026-07-11T12:00:00Z"))
	if msgs := lintOne(t, "date-invalid", iso); len(msgs) != 1 {
		t.Fatalf("ISO 8601 Date: %v", msgs)
	}
	badLM := https(mkResp(200, "Last-Modified", "yesterday"))
	msgs := lintOne(t, "date-invalid", badLM)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "Last-Modified") {
		t.Fatalf("invalid Last-Modified: %v", msgs)
	}
	ok := https(mkResp(200, "Date", "Sat, 11 Jul 2026 12:00:00 GMT"))
	if msgs := lintOne(t, "date-invalid", ok); len(msgs) != 0 {
		t.Fatalf("valid Date flagged: %v", msgs)
	}
	// Obsolete-but-parseable forms are a softer, separate finding.
	rfc850 := https(mkResp(200, "Date", "Saturday, 11-Jul-26 12:00:00 GMT"))
	msgs = lintOne(t, "date-obsolete-format", rfc850)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "RFC 850") {
		t.Fatalf("RFC 850 Date: %v", msgs)
	}
	asc := https(mkResp(200, "Expires", "Sat Jul 11 12:00:00 2026"))
	msgs = lintOne(t, "date-obsolete-format", asc)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "asctime") {
		t.Fatalf("asctime Expires: %v", msgs)
	}
	imf := https(mkResp(200, "Date", "Sat, 11 Jul 2026 12:00:00 GMT"))
	if msgs := lintOne(t, "date-obsolete-format", imf); len(msgs) != 0 {
		t.Fatalf("IMF-fixdate flagged: %v", msgs)
	}
}

func TestStatusSpecificHeaders(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		if msgs := lintOne(t, "redirect-location-missing", https(mkResp(code))); len(msgs) != 1 {
			t.Errorf("%d without Location: %v", code, msgs)
		}
	}
	with := https(mkResp(301, "Location", "https://example.test/new"))
	if msgs := lintOne(t, "redirect-location-missing", with); len(msgs) != 0 {
		t.Fatalf("redirect with Location flagged: %v", msgs)
	}
	// 300 Multiple Choices and 304 legitimately omit Location.
	if msgs := lintOne(t, "redirect-location-missing", https(mkResp(304))); len(msgs) != 0 {
		t.Fatalf("304 flagged: %v", msgs)
	}
	// 405 must enumerate the allowed methods.
	bare := https(mkResp(405))
	if msgs := lintOne(t, "allow-missing-405", bare); len(msgs) != 1 {
		t.Fatalf("405 without Allow: %v", msgs)
	}
	allowed := https(mkResp(405, "Allow", "GET, HEAD"))
	if msgs := lintOne(t, "allow-missing-405", allowed); len(msgs) != 0 {
		t.Fatalf("405 with Allow flagged: %v", msgs)
	}
	// Retry-After must be delta-seconds or an HTTP-date.
	for _, ok := range []string{"120", "0", "Sat, 11 Jul 2026 12:00:00 GMT"} {
		if msgs := lintOne(t, "retry-after-invalid", https(mkResp(503, "Retry-After", ok))); len(msgs) != 0 {
			t.Errorf("valid Retry-After %q flagged: %v", ok, msgs)
		}
	}
	for _, bad := range []string{"2 minutes", "-5", "later"} {
		if msgs := lintOne(t, "retry-after-invalid", https(mkResp(503, "Retry-After", bad))); len(msgs) != 1 {
			t.Errorf("Retry-After %q: %v", bad, msgs)
		}
	}
}

func TestFieldSyntaxRules(t *testing.T) {
	// "Name : value" — the space becomes part of the field name, which
	// RFC 9112 §5.1 explicitly calls out as invalid.
	spaced := https(&httpmsg.Response{StatusCode: 200, Fields: []httpmsg.Field{
		{Name: "X-Custom ", Value: "v"},
	}})
	msgs := lintOne(t, "field-name-invalid", spaced)
	if len(msgs) != 1 || !strings.Contains(msgs[0], `"X-Custom "`) {
		t.Fatalf("space before colon: %v", msgs)
	}
	noColon := https(&httpmsg.Response{StatusCode: 200, Fields: []httpmsg.Field{
		{Name: "this is not a header line", NoColon: true},
	}})
	if msgs := lintOne(t, "field-name-invalid", noColon); len(msgs) != 1 {
		t.Fatalf("colon-less line: %v", msgs)
	}
	// Forbidden bytes in values are reported with the offending byte.
	nul := https(&httpmsg.Response{StatusCode: 200, Fields: []httpmsg.Field{
		{Name: "X-Bad", Value: "abc\x00def"},
	}})
	msgs = lintOne(t, "field-value-invalid", nul)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "0x00") {
		t.Fatalf("NUL byte: %v", msgs)
	}
	// Obsolete line folding is flagged from the parser's ObsFolded mark.
	folded := https(&httpmsg.Response{StatusCode: 200, Fields: []httpmsg.Field{
		{Name: "X-Long", Value: "part one part two", ObsFolded: true},
	}})
	if msgs := lintOne(t, "obs-fold", folded); len(msgs) != 1 {
		t.Fatalf("obs-fold: %v", msgs)
	}
}

// TestExemplaryResponseIsClean is the integration guarantee behind
// examples/good.txt: a fully hardened response produces zero findings
// from the entire catalog.
func TestExemplaryResponseIsClean(t *testing.T) {
	resp := mkResp(200,
		"Date", "Sat, 11 Jul 2026 12:00:00 GMT",
		"Content-Type", "text/html; charset=utf-8",
		"Content-Length", "1234",
		"Cache-Control", "private, no-cache",
		"Strict-Transport-Security", "max-age=31536000; includeSubDomains",
		"Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options", "nosniff",
		"Referrer-Policy", "strict-origin-when-cross-origin",
		"ETag", `"v42"`,
		"Server", "nginx",
	)
	engine, _ := NewEngine(nil, nil)
	findings := engine.Run(https(resp))
	for _, f := range findings {
		t.Errorf("exemplary response triggered %s: %s", f.Rule.ID, f.Message)
	}
}
