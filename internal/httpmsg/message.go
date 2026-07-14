// Package httpmsg models captured HTTP responses and parses the two offline
// capture formats hdrlint accepts: raw header dumps (curl -i / curl -D /
// devtools copy-paste) and HAR archives. Parsing is lossless where it
// matters for linting: field order, duplicates, obsolete line folding, and
// even colon-less garbage lines are preserved so the rule engine — not the
// parser — decides what is a violation.
package httpmsg

import (
	"fmt"
	"strings"
)

// Field is a single header field line, as captured.
type Field struct {
	// Name is the field name exactly as written (case preserved).
	Name string
	// Value is the field value with surrounding optional whitespace
	// trimmed, per RFC 9110 §5.5. Interior bytes are untouched.
	Value string
	// ObsFolded is true when the value was continued onto following
	// lines with leading whitespace (obs-fold, RFC 9112 §5.2).
	ObsFolded bool
	// NoColon is true when the line had no colon at all; Name then
	// holds the whole raw line and Value is empty.
	NoColon bool
}

// Response is one captured HTTP response: a status line (when present)
// plus its header fields in original order.
type Response struct {
	// Source identifies where the response came from (file path or "-").
	Source string
	// Index is the 1-based position of the response within its source.
	Index int
	// Proto is the protocol from the status line ("HTTP/1.1"), or ""
	// for headers-only captures.
	Proto string
	// StatusCode is the status from the status line, or 0 when the
	// capture had no status line (a bare header paste).
	StatusCode int
	// Reason is the reason phrase, possibly empty.
	Reason string
	// Fields are the header field lines in capture order.
	Fields []Field
	// URL is the request URL when known (HAR captures only).
	URL string
}

// Get returns the first value of the named field, case-insensitively.
func (r *Response) Get(name string) (string, bool) {
	for _, f := range r.Fields {
		if !f.NoColon && strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

// Values returns every value of the named field, in capture order.
func (r *Response) Values(name string) []string {
	var out []string
	for _, f := range r.Fields {
		if !f.NoColon && strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// Has reports whether the named field is present at least once.
func (r *Response) Has(name string) bool {
	_, ok := r.Get(name)
	return ok
}

// StatusLine reconstructs a human-readable status line, or a placeholder
// for headers-only captures.
func (r *Response) StatusLine() string {
	if r.StatusCode == 0 {
		return "(headers only)"
	}
	line := fmt.Sprintf("%s %d", r.Proto, r.StatusCode)
	if r.Reason != "" {
		line += " " + r.Reason
	}
	return line
}

// Label is the stable identifier used in reports: the request URL when the
// capture knows it (HAR), otherwise source plus response index.
func (r *Response) Label() string {
	if r.URL != "" {
		return r.URL
	}
	return fmt.Sprintf("%s#%d", r.Source, r.Index)
}
