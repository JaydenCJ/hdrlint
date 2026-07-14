// Tests for the raw capture parser: curl -i / curl -sD - dumps, redirect
// chains, devtools pastes, obs-fold, and garbage handling.
package httpmsg

import (
	"strings"
	"testing"
)

func TestParseRawSingleResponse(t *testing.T) {
	in := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: max-age=60\r\n\r\n"
	resps, err := ParseRaw([]byte(in), "cap.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	r := resps[0]
	if r.Proto != "HTTP/1.1" || r.StatusCode != 200 || r.Reason != "OK" {
		t.Fatalf("status line parsed as %q %d %q", r.Proto, r.StatusCode, r.Reason)
	}
	if v, ok := r.Get("content-type"); !ok || v != "text/html" {
		t.Fatalf("Content-Type = (%q, %v)", v, ok)
	}
	if r.Source != "cap.txt" || r.Index != 1 {
		t.Fatalf("source/index = %q/%d", r.Source, r.Index)
	}
	// curl prints "HTTP/2 200" — no minor version, no reason phrase.
	resps, err = ParseRaw([]byte("HTTP/2 200\nserver: envoy\n"), "cap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resps[0].Proto != "HTTP/2" || resps[0].StatusCode != 200 || resps[0].Reason != "" {
		t.Fatalf("HTTP/2 status line parsed as %+v", resps[0])
	}
}

func TestParseRawRedirectChain(t *testing.T) {
	// curl -sD - style: consecutive header blocks separated by blank lines.
	in := strings.Join([]string{
		"HTTP/1.1 301 Moved Permanently",
		"Location: https://example.test/",
		"Content-Length: 0",
		"",
		"HTTP/1.1 200 OK",
		"Content-Type: text/plain",
		"",
	}, "\r\n")
	resps, err := ParseRaw([]byte(in), "chain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2", len(resps))
	}
	if resps[0].StatusCode != 301 || resps[1].StatusCode != 200 {
		t.Fatalf("statuses = %d, %d", resps[0].StatusCode, resps[1].StatusCode)
	}
	if resps[1].Index != 2 {
		t.Fatalf("second response index = %d, want 2", resps[1].Index)
	}
}

func TestParseRawSkipsBodyBetweenResponses(t *testing.T) {
	// curl -iL keeps bodies inline; body lines — even ones that look like
	// headers — must not leak into the next response's fields.
	in := strings.Join([]string{
		"HTTP/1.1 302 Found",
		"Location: /next",
		"",
		"You are being redirected.",
		"Fake-Header: from the body",
		"",
		"HTTP/1.1 200 OK",
		"Content-Type: text/plain",
		"",
		"hello",
	}, "\n")
	resps, err := ParseRaw([]byte(in), "cap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2", len(resps))
	}
	if resps[0].Has("Fake-Header") || resps[1].Has("Fake-Header") {
		t.Fatal("body line was parsed as a header field")
	}
}

func TestParseRawHeadersOnlyCapture(t *testing.T) {
	// A devtools copy-paste has no status line; blank lines within the
	// paste are tolerated because pastes never carry a body.
	in := "Content-Type: application/json\nX-Request-Id: 42\n\nServer: envoy\n"
	resps, err := ParseRaw([]byte(in), "paste")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	r := resps[0]
	if r.StatusCode != 0 {
		t.Fatalf("StatusCode = %d, want 0 (unknown)", r.StatusCode)
	}
	if !r.Has("Server") {
		t.Fatal("field after the stray blank line was dropped")
	}
	if r.StatusLine() != "(headers only)" {
		t.Fatalf("StatusLine() = %q", r.StatusLine())
	}
}

func TestParseRawObsFold(t *testing.T) {
	in := "HTTP/1.1 200 OK\nX-Long: part one\n and part two\n\n"
	resps, err := ParseRaw([]byte(in), "cap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, _ := resps[0].Get("X-Long")
	if v != "part one and part two" {
		t.Fatalf("folded value = %q", v)
	}
	if !resps[0].Fields[0].ObsFolded {
		t.Fatal("ObsFolded flag not set — the obs-fold rule needs it")
	}
}

func TestParseRawKeepsColonlessLines(t *testing.T) {
	// Garbage inside a header block is preserved (NoColon) so the
	// field-name-invalid rule can report it; it must not vanish.
	in := "HTTP/1.1 200 OK\nGood: yes\nthis line has no colon\n\n"
	resps, err := ParseRaw([]byte(in), "cap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, f := range resps[0].Fields {
		if f.NoColon && f.Name == "this line has no colon" {
			found = true
		}
	}
	if !found {
		t.Fatal("colon-less line was not preserved")
	}
	// And it must be invisible to Get/Has.
	if resps[0].Has("this line has no colon") {
		t.Fatal("NoColon garbage leaked into header lookup")
	}
}

func TestParseRawRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "\n\n", "just some prose\nwithout headers\n"} {
		if _, err := ParseRaw([]byte(in), "cap"); err == nil {
			t.Errorf("ParseRaw(%q) succeeded, want error", in)
		}
	}
}

func TestResponseHelpersAreCaseInsensitive(t *testing.T) {
	r := &Response{Fields: []Field{
		{Name: "Set-Cookie", Value: "a=1"},
		{Name: "SET-COOKIE", Value: "b=2"},
	}}
	if v, ok := r.Get("set-cookie"); !ok || v != "a=1" {
		t.Fatalf("Get = (%q, %v), want first value", v, ok)
	}
	if got := r.Values("Set-Cookie"); len(got) != 2 || got[1] != "b=2" {
		t.Fatalf("Values = %v", got)
	}
	if !r.Has("sEt-CoOkIe") {
		t.Fatal("Has is not case-insensitive")
	}
	// Labels: raw captures use source#index, HAR captures use the URL.
	raw := &Response{Source: "cap.txt", Index: 3}
	if raw.Label() != "cap.txt#3" {
		t.Fatalf("raw label = %q", raw.Label())
	}
	har := &Response{Source: "a.har", Index: 1, URL: "https://example.test/x"}
	if har.Label() != "https://example.test/x" {
		t.Fatalf("HAR label = %q", har.Label())
	}
}
