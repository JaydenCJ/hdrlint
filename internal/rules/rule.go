// Package rules defines the hdrlint rule engine and its rule catalog.
// Every rule carries a citation to the spec that makes the finding true —
// an IETF RFC wherever one governs, otherwise the WHATWG/W3C standard —
// so a report line is always an argument, never an opinion.
package rules

import (
	"fmt"
	"sort"

	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
)

// Severity ranks findings. Error marks spec violations (MUST-level) and
// exploitable misconfigurations; Warn marks SHOULD-level problems and
// risky defaults; Info marks advice and hardening opportunities.
type Severity int

// Severity levels, ordered so that higher is more severe.
const (
	Info Severity = iota
	Warn
	Error
)

// String renders the severity the way reports and --fail-on spell it.
func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// ParseSeverity parses a --fail-on style severity name.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "error":
		return Error, nil
	case "warn":
		return Warn, nil
	case "info":
		return Info, nil
	}
	return Info, fmt.Errorf("unknown severity %q (want error, warn, or info)", s)
}

// Citation names the governing spec for a rule.
type Citation struct {
	// Spec is the document name: "RFC 9110", "W3C CSP3", "WHATWG Fetch".
	Spec string `json:"spec"`
	// Section is the section number within the spec, or "" when the
	// document has no stable section numbering.
	Section string `json:"section,omitempty"`
	// URL points at the cited text.
	URL string `json:"url"`
}

// RFC builds a citation for an IETF RFC section, deriving the canonical
// rfc-editor URL.
func RFC(num int, section string) Citation {
	c := Citation{
		Spec:    fmt.Sprintf("RFC %d", num),
		Section: section,
		URL:     fmt.Sprintf("https://www.rfc-editor.org/rfc/rfc%d", num),
	}
	if section != "" {
		c.URL += "#section-" + section
	}
	return c
}

// String renders the citation for report lines: "RFC 9110 §8.8.3".
func (c Citation) String() string {
	if c.Section == "" {
		return c.Spec
	}
	return c.Spec + " §" + c.Section
}

// Target is one response under lint plus the transport context the rules
// need: whether the capture is known (or assumed) to be HTTPS.
type Target struct {
	Resp  *httpmsg.Response
	HTTPS bool
}

// Rule is a single check. Check returns zero or more finding messages;
// the engine attaches severity and citation from the rule itself.
type Rule struct {
	// ID is the stable lowercase-hyphen identifier used by --disable,
	// --only, and `hdrlint explain`.
	ID string
	// Category is "security", "caching", or "correctness".
	Category string
	// Severity is the rule's fixed severity.
	Severity Severity
	// HTTPSOnly rules are skipped for plain-HTTP captures (--http).
	HTTPSOnly bool
	// HTTPOnly rules run only for plain-HTTP captures.
	HTTPOnly bool
	// Summary is the one-line description shown by `hdrlint rules`.
	Summary string
	// Advice is the remediation paragraph shown by `hdrlint explain`.
	Advice string
	// Cite is the governing spec for this rule.
	Cite Citation
	// Check inspects the target and returns finding messages.
	Check func(t *Target) []string
}

// Finding is one triggered rule instance on one response.
type Finding struct {
	Rule    *Rule
	Message string
}

// Categories in display order.
var Categories = []string{"security", "caching", "correctness"}

// All returns the full rule catalog in stable order: by category
// (security, caching, correctness), then by ID.
func All() []*Rule {
	var out []*Rule
	out = append(out, securityRules()...)
	out = append(out, cachingRules()...)
	out = append(out, correctnessRules()...)
	order := map[string]int{}
	for i, c := range Categories {
		order[c] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return order[out[i].Category] < order[out[j].Category]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ByID looks a rule up by its identifier.
func ByID(id string) (*Rule, bool) {
	for _, r := range All() {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// Engine runs a filtered rule set against targets.
type Engine struct {
	rules []*Rule
}

// NewEngine builds an engine from the catalog, minus disabled rules; when
// only is non-empty, exactly those rules run. Unknown IDs are reported so
// a typo in CI configuration fails loudly instead of silently passing.
func NewEngine(disabled, only []string) (*Engine, error) {
	known := map[string]*Rule{}
	catalog := All()
	for _, r := range catalog {
		known[r.ID] = r
	}
	for _, id := range append(append([]string{}, disabled...), only...) {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("unknown rule id %q (run `hdrlint rules` for the catalog)", id)
		}
	}
	skip := map[string]bool{}
	for _, id := range disabled {
		skip[id] = true
	}
	keep := map[string]bool{}
	for _, id := range only {
		keep[id] = true
	}
	e := &Engine{}
	for _, r := range catalog {
		if skip[r.ID] {
			continue
		}
		if len(keep) > 0 && !keep[r.ID] {
			continue
		}
		e.rules = append(e.rules, r)
	}
	return e, nil
}

// Len reports how many rules the engine will run.
func (e *Engine) Len() int { return len(e.rules) }

// Run lints one target. Findings are sorted by severity (most severe
// first), then rule ID, then message, so output is deterministic.
func (e *Engine) Run(t *Target) []Finding {
	var findings []Finding
	for _, r := range e.rules {
		if r.HTTPSOnly && !t.HTTPS {
			continue
		}
		if r.HTTPOnly && t.HTTPS {
			continue
		}
		for _, msg := range r.Check(t) {
			findings = append(findings, Finding{Rule: r, Message: msg})
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Rule.Severity != b.Rule.Severity {
			return a.Rule.Severity > b.Rule.Severity
		}
		if a.Rule.ID != b.Rule.ID {
			return a.Rule.ID < b.Rule.ID
		}
		return a.Message < b.Message
	})
	return findings
}
