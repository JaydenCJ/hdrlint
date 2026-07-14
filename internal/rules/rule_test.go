// Engine and catalog tests: identifier hygiene, citation integrity,
// filtering, and deterministic ordering. Rule-specific behavior lives in
// security_test.go, caching_test.go, and correctness_test.go.
package rules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
)

// mkResp builds an in-memory response from name/value pairs.
func mkResp(status int, headers ...string) *httpmsg.Response {
	if len(headers)%2 != 0 {
		panic("mkResp: headers must be name/value pairs")
	}
	r := &httpmsg.Response{Source: "test", Index: 1, Proto: "HTTP/1.1", StatusCode: status}
	for i := 0; i < len(headers); i += 2 {
		r.Fields = append(r.Fields, httpmsg.Field{Name: headers[i], Value: headers[i+1]})
	}
	return r
}

// lintOne runs exactly one rule against a target and returns the finding
// messages, so each rule test is isolated from the rest of the catalog.
func lintOne(t *testing.T, id string, target *Target) []string {
	t.Helper()
	engine, err := NewEngine(nil, []string{id})
	if err != nil {
		t.Fatalf("NewEngine(only=%s): %v", id, err)
	}
	var msgs []string
	for _, f := range engine.Run(target) {
		msgs = append(msgs, f.Message)
	}
	return msgs
}

// https wraps a response in an HTTPS target, the common case.
func https(r *httpmsg.Response) *Target { return &Target{Resp: r, HTTPS: true} }

func TestCatalogIntegrity(t *testing.T) {
	idRe := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	catalog := All()
	if len(catalog) < 40 {
		t.Fatalf("catalog has %d rules; expected the full set", len(catalog))
	}
	seen := map[string]bool{}
	validCat := map[string]bool{}
	for _, c := range Categories {
		validCat[c] = true
	}
	for _, r := range catalog {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if !idRe.MatchString(r.ID) {
			t.Errorf("rule id %q is not lowercase-hyphen", r.ID)
		}
		if !validCat[r.Category] {
			t.Errorf("rule %s has unknown category %q", r.ID, r.Category)
		}
		if r.Summary == "" || r.Advice == "" {
			t.Errorf("rule %s lacks summary or advice", r.ID)
		}
		if r.Cite.Spec == "" || r.Cite.URL == "" {
			t.Errorf("rule %s lacks a citation — citations are the point", r.ID)
		}
		if r.Check == nil {
			t.Errorf("rule %s has no check function", r.ID)
		}
		if r.HTTPSOnly && r.HTTPOnly {
			t.Errorf("rule %s claims to be both HTTPS-only and HTTP-only", r.ID)
		}
	}
	// ByID must resolve real rules and reject unknown ones.
	if r, ok := ByID("etag-malformed"); !ok || r.ID != "etag-malformed" {
		t.Error("ByID failed to find a real rule")
	}
	if _, ok := ByID("no-such-rule"); ok {
		t.Error("ByID found a rule that does not exist")
	}
}

func TestCatalogOrderIsStable(t *testing.T) {
	a, b := All(), All()
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("catalog order differs between calls at index %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
	// Categories group in display order, IDs sorted within each.
	lastCat, lastID := -1, ""
	order := map[string]int{}
	for i, c := range Categories {
		order[c] = i
	}
	for _, r := range a {
		c := order[r.Category]
		if c < lastCat {
			t.Fatalf("category order broken at rule %s", r.ID)
		}
		if c > lastCat {
			lastCat, lastID = c, ""
		}
		if r.ID < lastID {
			t.Fatalf("rule IDs not sorted within category at %s", r.ID)
		}
		lastID = r.ID
	}
}

func TestRFCCitationURLDerivation(t *testing.T) {
	c := RFC(9110, "8.8.3")
	if c.Spec != "RFC 9110" || c.Section != "8.8.3" {
		t.Fatalf("citation = %+v", c)
	}
	if c.URL != "https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3" {
		t.Fatalf("URL = %q", c.URL)
	}
	if c.String() != "RFC 9110 §8.8.3" {
		t.Fatalf("String() = %q", c.String())
	}
	sectionless := Citation{Spec: "WHATWG Fetch", URL: "https://fetch.spec.whatwg.org/"}
	if sectionless.String() != "WHATWG Fetch" {
		t.Fatalf("sectionless String() = %q", sectionless.String())
	}
}

func TestEngineRejectsUnknownRuleIDs(t *testing.T) {
	if _, err := NewEngine([]string{"typo-rule"}, nil); err == nil {
		t.Error("unknown --disable id accepted; CI typos would silently pass")
	}
	if _, err := NewEngine(nil, []string{"typo-rule"}); err == nil {
		t.Error("unknown --only id accepted")
	}
}

func TestEngineDisableAndOnly(t *testing.T) {
	all, _ := NewEngine(nil, nil)
	disabled, _ := NewEngine([]string{"hsts-missing"}, nil)
	if disabled.Len() != all.Len()-1 {
		t.Fatalf("disable: %d rules, want %d", disabled.Len(), all.Len()-1)
	}
	only, _ := NewEngine(nil, []string{"etag-malformed", "hsts-missing"})
	if only.Len() != 2 {
		t.Fatalf("only: %d rules, want 2", only.Len())
	}
	// A disabled rule must produce no findings even when it would fire.
	target := https(mkResp(200, "Content-Type", "text/plain"))
	for _, f := range disabled.Run(target) {
		if f.Rule.ID == "hsts-missing" {
			t.Fatal("disabled rule still fired")
		}
	}
}

func TestFindingsSortedBySeverityThenRuleID(t *testing.T) {
	// This response triggers rules at every severity level.
	target := https(mkResp(200,
		"Content-Type", "text/html",
		"ETag", "unquoted",
		"Server", "nginx/1.25.3",
	))
	engine, _ := NewEngine(nil, nil)
	findings := engine.Run(target)
	if len(findings) < 3 {
		t.Fatalf("expected several findings, got %d", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		prev, cur := findings[i-1], findings[i]
		if cur.Rule.Severity > prev.Rule.Severity {
			t.Fatalf("severity order broken: %s before %s", prev.Rule.ID, cur.Rule.ID)
		}
		if cur.Rule.Severity == prev.Rule.Severity && cur.Rule.ID < prev.Rule.ID {
			t.Fatalf("rule id order broken: %s before %s", prev.Rule.ID, cur.Rule.ID)
		}
	}
}

func TestHTTPSOnlyAndHTTPOnlyGating(t *testing.T) {
	resp := mkResp(200,
		"Content-Type", "text/plain",
		"Strict-Transport-Security", "max-age=31536000",
		"Set-Cookie", "id=1; Path=/",
	)
	engine, _ := NewEngine(nil, nil)

	httpsIDs := map[string]bool{}
	for _, f := range engine.Run(&Target{Resp: resp, HTTPS: true}) {
		httpsIDs[f.Rule.ID] = true
	}
	httpIDs := map[string]bool{}
	for _, f := range engine.Run(&Target{Resp: resp, HTTPS: false}) {
		httpIDs[f.Rule.ID] = true
	}
	if !httpsIDs["cookie-no-secure"] {
		t.Error("cookie-no-secure should fire on HTTPS")
	}
	if httpIDs["cookie-no-secure"] {
		t.Error("cookie-no-secure must be skipped for plain-HTTP captures")
	}
	if !httpIDs["hsts-over-http"] {
		t.Error("hsts-over-http should fire on plain HTTP")
	}
	if httpsIDs["hsts-over-http"] {
		t.Error("hsts-over-http must not fire on HTTPS")
	}
}

func TestParseSeverity(t *testing.T) {
	for name, want := range map[string]Severity{"error": Error, "warn": Warn, "info": Info} {
		got, err := ParseSeverity(name)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = (%v, %v)", name, got, err)
		}
	}
	if _, err := ParseSeverity("fatal"); err == nil || !strings.Contains(err.Error(), "fatal") {
		t.Errorf("ParseSeverity(fatal) err = %v, want descriptive error", err)
	}
}
