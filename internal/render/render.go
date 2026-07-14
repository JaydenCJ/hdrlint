// Package render turns lint results into the three output formats:
// aligned text for humans, stable JSON (schema_version 1) for machines,
// and GitHub Actions workflow commands for inline CI annotations.
package render

import (
	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
	"github.com/JaydenCJ/hdrlint/internal/rules"
)

// ResponseResult pairs one linted response with its findings.
type ResponseResult struct {
	Resp     *httpmsg.Response
	Findings []rules.Finding
}

// Summary counts findings across all responses.
type Summary struct {
	Responses int `json:"responses"`
	Errors    int `json:"errors"`
	Warnings  int `json:"warnings"`
	Notices   int `json:"notices"`
}

// Summarize tallies a result set.
func Summarize(results []ResponseResult) Summary {
	s := Summary{Responses: len(results)}
	for _, r := range results {
		for _, f := range r.Findings {
			switch f.Rule.Severity {
			case rules.Error:
				s.Errors++
			case rules.Warn:
				s.Warnings++
			default:
				s.Notices++
			}
		}
	}
	return s
}

// Total is the number of findings of every severity.
func (s Summary) Total() int { return s.Errors + s.Warnings + s.Notices }
