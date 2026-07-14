// Tests for the three report renderers: text alignment and summary math,
// JSON schema stability, and GitHub workflow-command escaping.
package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
	"github.com/JaydenCJ/hdrlint/internal/rules"
	"github.com/JaydenCJ/hdrlint/internal/version"
)

// fixtureResults builds a deterministic two-response result set by
// running the real engine on hand-built responses.
func fixtureResults(t *testing.T) []ResponseResult {
	t.Helper()
	engine, err := rules.NewEngine(nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bad := &httpmsg.Response{
		Source: "cap.txt", Index: 1, Proto: "HTTP/1.1", StatusCode: 200, Reason: "OK",
		Fields: []httpmsg.Field{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Date", Value: "Sat, 11 Jul 2026 12:00:00 GMT"},
			{Name: "ETag", Value: "unquoted"},
			{Name: "Cache-Control", Value: "no-store, max-age=60"},
			{Name: "Server", Value: "nginx/1.25.3"},
		},
	}
	clean := &httpmsg.Response{
		Source: "cap.txt", Index: 2, Proto: "HTTP/1.1", StatusCode: 204, Reason: "No Content",
		Fields: []httpmsg.Field{
			{Name: "Date", Value: "Sat, 11 Jul 2026 12:00:00 GMT"},
			{Name: "Strict-Transport-Security", Value: "max-age=31536000"},
			{Name: "X-Content-Type-Options", Value: "nosniff"},
		},
	}
	return []ResponseResult{
		{Resp: bad, Findings: engine.Run(&rules.Target{Resp: bad, HTTPS: true})},
		{Resp: clean, Findings: engine.Run(&rules.Target{Resp: clean, HTTPS: true})},
	}
}

func TestSummarize(t *testing.T) {
	results := fixtureResults(t)
	s := Summarize(results)
	if s.Responses != 2 {
		t.Fatalf("responses = %d", s.Responses)
	}
	if s.Errors == 0 || s.Total() != s.Errors+s.Warnings+s.Notices {
		t.Fatalf("summary math broken: %+v", s)
	}
	// The 204 response is fully clean; all findings belong to response 1.
	if len(results[1].Findings) != 0 {
		t.Fatalf("clean 204 has findings: %v", results[1].Findings)
	}
}

func TestTextReport(t *testing.T) {
	var b strings.Builder
	results := fixtureResults(t)
	Text(&b, results, 50)
	out := b.String()
	for _, want := range []string{
		"cap.txt#1  HTTP/1.1 200 OK",
		"cap.txt#2  HTTP/1.1 204 No Content",
		"ok — no findings",
		"etag-malformed",
		"[RFC 9110 §8.8.3]",
		"against 50 rules",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("text report contains ANSI escapes; must be CI-log safe")
	}
	// Byte-identical output on identical input, run to run.
	var again strings.Builder
	Text(&again, fixtureResults(t), 50)
	if again.String() != out {
		t.Fatal("identical input produced different text reports")
	}
}

func TestJSONReportSchema(t *testing.T) {
	var b strings.Builder
	if err := JSON(&b, fixtureResults(t)); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var env struct {
		Tool          string `json:"tool"`
		Version       string `json:"version"`
		SchemaVersion int    `json:"schema_version"`
		Responses     []struct {
			Source   string `json:"source"`
			Index    int    `json:"index"`
			Status   int    `json:"status"`
			Findings []struct {
				Rule     string `json:"rule"`
				Severity string `json:"severity"`
				Category string `json:"category"`
				Message  string `json:"message"`
				Citation struct {
					Spec    string `json:"spec"`
					Section string `json:"section"`
					URL     string `json:"url"`
				} `json:"citation"`
			} `json:"findings"`
		} `json:"responses"`
		Summary Summary `json:"summary"`
	}
	if err := json.Unmarshal([]byte(b.String()), &env); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if env.Tool != "hdrlint" || env.Version != version.Version || env.SchemaVersion != 1 {
		t.Fatalf("envelope = %s/%s/%d", env.Tool, env.Version, env.SchemaVersion)
	}
	if len(env.Responses) != 2 {
		t.Fatalf("got %d responses", len(env.Responses))
	}
	found := false
	for _, f := range env.Responses[0].Findings {
		if f.Rule == "etag-malformed" {
			found = true
			if f.Citation.Spec != "RFC 9110" || f.Citation.Section != "8.8.3" || !strings.Contains(f.Citation.URL, "rfc9110") {
				t.Errorf("etag citation = %+v", f.Citation)
			}
		}
	}
	if !found {
		t.Fatal("etag-malformed finding missing from JSON")
	}
	// The clean response must serialize with an empty findings array,
	// not null — consumers index into it unconditionally.
	if !strings.Contains(b.String(), `"findings": []`) {
		t.Error("empty findings serialized as null, want []")
	}
}

func TestGitHubFormat(t *testing.T) {
	var b strings.Builder
	GitHub(&b, fixtureResults(t))
	out := b.String()
	if !strings.Contains(out, "::error title=hdrlint etag-malformed::") {
		t.Fatalf("missing error annotation:\n%s", out)
	}
	if !strings.Contains(out, "::warning ") || !strings.Contains(out, "::notice ") {
		t.Errorf("severity levels not mapped:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "::") {
			t.Errorf("non-command line in github output: %q", line)
		}
	}
}

func TestGitHubEscaping(t *testing.T) {
	// Workflow commands break on raw %, CR, LF in data and on : , in
	// property values — a hostile header value must not forge commands.
	r := &httpmsg.Response{Source: "cap", Index: 1, StatusCode: 200}
	// Build a finding manually to control the message content.
	rule, _ := rules.ByID("field-value-invalid")
	results := []ResponseResult{{
		Resp:     r,
		Findings: []rules.Finding{{Rule: rule, Message: "value has 100%\nnewline, and: colon"}},
	}}
	var b strings.Builder
	GitHub(&b, results)
	out := b.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("newline in message was not escaped:\n%q", out)
	}
	if !strings.Contains(out, "100%25%0Anewline") {
		t.Fatalf("data escaping wrong: %q", out)
	}
}

func TestCatalogAndExplainRenderers(t *testing.T) {
	var b strings.Builder
	RulesText(&b, rules.All())
	out := b.String()
	for _, want := range []string{"security (", "caching (", "correctness (", "etag-malformed", "rules total"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules listing missing %q", want)
		}
	}
	// JSON catalog: one entry per rule, valid JSON.
	var jb strings.Builder
	if err := RulesJSON(&jb, rules.All()); err != nil {
		t.Fatalf("RulesJSON: %v", err)
	}
	var list []struct {
		ID       string `json:"id"`
		Category string `json:"category"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal([]byte(jb.String()), &list); err != nil {
		t.Fatalf("rules JSON invalid: %v", err)
	}
	if len(list) != len(rules.All()) {
		t.Fatalf("rules JSON has %d entries, want %d", len(list), len(rules.All()))
	}
	// Explain: full advice plus the citation and its URL.
	r, _ := rules.ByID("etag-malformed")
	var eb strings.Builder
	ExplainText(&eb, r)
	out = eb.String()
	for _, want := range []string{"etag-malformed", "(caching, error)", "citation: RFC 9110 §8.8.3", "https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q\n---\n%s", want, out)
		}
	}
}
