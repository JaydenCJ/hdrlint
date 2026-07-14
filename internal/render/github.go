package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/rules"
)

// GitHub writes findings as GitHub Actions workflow commands, one per
// line, so a plain `hdrlint check --format github` step annotates the run
// without any marketplace action. Severities map to ::error, ::warning,
// and ::notice.
func GitHub(w io.Writer, results []ResponseResult) {
	for _, r := range results {
		for _, f := range r.Findings {
			fmt.Fprintf(w, "::%s title=%s::%s\n",
				githubLevel(f.Rule.Severity),
				escapeProperty("hdrlint "+f.Rule.ID),
				escapeData(fmt.Sprintf("%s: %s [%s]", r.Resp.Label(), f.Message, f.Rule.Cite)))
		}
	}
}

// githubLevel maps a severity onto a workflow-command level.
func githubLevel(s rules.Severity) string {
	switch s {
	case rules.Error:
		return "error"
	case rules.Warn:
		return "warning"
	default:
		return "notice"
	}
}

// escapeData escapes message data per the workflow-command rules.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes property values, which additionally must encode
// ':' and ','.
func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
