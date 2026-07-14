package render

import (
	"encoding/json"
	"io"

	"github.com/JaydenCJ/hdrlint/internal/rules"
	"github.com/JaydenCJ/hdrlint/internal/version"
)

// jsonEnvelope is the top-level JSON report. schema_version is bumped
// only on breaking shape changes, so CI consumers can pin against it.
type jsonEnvelope struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	SchemaVersion int            `json:"schema_version"`
	Responses     []jsonResponse `json:"responses"`
	Summary       Summary        `json:"summary"`
}

type jsonResponse struct {
	Source   string        `json:"source"`
	Index    int           `json:"index"`
	URL      string        `json:"url,omitempty"`
	Status   int           `json:"status"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Category string         `json:"category"`
	Message  string         `json:"message"`
	Citation rules.Citation `json:"citation"`
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, results []ResponseResult) error {
	env := jsonEnvelope{
		Tool:          "hdrlint",
		Version:       version.Version,
		SchemaVersion: 1,
		Responses:     []jsonResponse{},
		Summary:       Summarize(results),
	}
	for _, r := range results {
		jr := jsonResponse{
			Source:   r.Resp.Source,
			Index:    r.Resp.Index,
			URL:      r.Resp.URL,
			Status:   r.Resp.StatusCode,
			Findings: []jsonFinding{},
		}
		for _, f := range r.Findings {
			jr.Findings = append(jr.Findings, jsonFinding{
				Rule:     f.Rule.ID,
				Severity: f.Rule.Severity.String(),
				Category: f.Rule.Category,
				Message:  f.Message,
				Citation: f.Rule.Cite,
			})
		}
		env.Responses = append(env.Responses, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// jsonRule is the `hdrlint rules --format json` row.
type jsonRule struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Severity string         `json:"severity"`
	Summary  string         `json:"summary"`
	Citation rules.Citation `json:"citation"`
}

// RulesJSON writes the rule catalog as JSON.
func RulesJSON(w io.Writer, catalog []*rules.Rule) error {
	out := make([]jsonRule, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, jsonRule{
			ID:       r.ID,
			Category: r.Category,
			Severity: r.Severity.String(),
			Summary:  r.Summary,
			Citation: r.Cite,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
