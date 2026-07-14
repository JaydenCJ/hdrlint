package render

import (
	"fmt"
	"io"

	"github.com/JaydenCJ/hdrlint/internal/rules"
)

// Text writes the human-readable report: one block per response with
// aligned columns, then a one-line summary. Output is plain ASCII/UTF-8
// with no ANSI escapes, so it is safe for CI logs and byte-stable.
func Text(w io.Writer, results []ResponseResult, ruleCount int) {
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  %s\n", r.Resp.Label(), r.Resp.StatusLine())
		if len(r.Findings) == 0 {
			fmt.Fprintln(w, "  ok — no findings")
			continue
		}
		idWidth := 0
		for _, f := range r.Findings {
			if len(f.Rule.ID) > idWidth {
				idWidth = len(f.Rule.ID)
			}
		}
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  %-5s %-*s  %s  [%s]\n",
				f.Rule.Severity, idWidth, f.Rule.ID, f.Message, f.Rule.Cite)
		}
	}
	s := Summarize(results)
	fmt.Fprintf(w, "\nchecked %d %s against %d rules: %d %s, %d %s, %d %s\n",
		s.Responses, plural(s.Responses, "response", "responses"), ruleCount,
		s.Errors, plural(s.Errors, "error", "errors"),
		s.Warnings, plural(s.Warnings, "warning", "warnings"),
		s.Notices, plural(s.Notices, "notice", "notices"))
}

// plural picks the right noun form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// RulesText writes the rule catalog grouped by category, for
// `hdrlint rules`.
func RulesText(w io.Writer, catalog []*rules.Rule) {
	byCat := map[string][]*rules.Rule{}
	for _, r := range catalog {
		byCat[r.Category] = append(byCat[r.Category], r)
	}
	first := true
	for _, cat := range rules.Categories {
		list := byCat[cat]
		if len(list) == 0 {
			continue
		}
		if !first {
			fmt.Fprintln(w)
		}
		first = false
		fmt.Fprintf(w, "%s (%d %s)\n", cat, len(list), plural(len(list), "rule", "rules"))
		idWidth := 0
		for _, r := range list {
			if len(r.ID) > idWidth {
				idWidth = len(r.ID)
			}
		}
		for _, r := range list {
			fmt.Fprintf(w, "  %-5s %-*s  %s  [%s]\n", r.Severity, idWidth, r.ID, r.Summary, r.Cite)
		}
	}
	fmt.Fprintf(w, "\n%d rules total; `hdrlint explain <id>` shows advice and the cited text\n", len(catalog))
}

// ExplainText writes the full description of one rule.
func ExplainText(w io.Writer, r *rules.Rule) {
	fmt.Fprintf(w, "%s  (%s, %s)\n\n", r.ID, r.Category, r.Severity)
	fmt.Fprintf(w, "  %s.\n\n", r.Summary)
	fmt.Fprintf(w, "  %s\n\n", r.Advice)
	fmt.Fprintf(w, "  citation: %s\n", r.Cite)
	fmt.Fprintf(w, "  %s\n", r.Cite.URL)
}
