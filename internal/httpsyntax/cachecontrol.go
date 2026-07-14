package httpsyntax

import (
	"fmt"
	"strings"
)

// Directive is one parsed Cache-Control directive.
type Directive struct {
	// Name is the directive name, lowercased (directive names are
	// case-insensitive per RFC 9111 §5.2).
	Name string
	// Value is the argument with quotes resolved, or "" without one.
	Value string
	// HasValue distinguishes `no-cache` from `no-cache=""`.
	HasValue bool
	// Quoted is true when the argument used the quoted-string form,
	// which senders SHOULD NOT generate for delta-seconds arguments.
	Quoted bool
}

// ParseCacheControl splits a Cache-Control field value into directives and
// collects grammar-level problems (empty list elements, names that are not
// tokens, unterminated quotes). Commas inside quoted strings do not split,
// so `private="set-cookie, authorization"` parses as one directive.
func ParseCacheControl(v string) ([]Directive, []string) {
	var dirs []Directive
	var problems []string
	for _, item := range splitList(v) {
		item = strings.Trim(item, " \t")
		if item == "" {
			// RFC 9110 §5.6.1: senders MUST NOT generate empty
			// list elements ("max-age=60,,no-cache").
			problems = append(problems, "empty list element (doubled or trailing comma)")
			continue
		}
		name, arg, has := strings.Cut(item, "=")
		name = strings.Trim(name, " \t")
		d := Directive{Name: strings.ToLower(name), HasValue: has}
		if !IsToken(name) {
			problems = append(problems, fmt.Sprintf("directive name %q is not a valid token", name))
		}
		if has {
			arg = strings.Trim(arg, " \t")
			if strings.HasPrefix(arg, `"`) {
				unq, ok := Unquote(arg)
				if !ok {
					problems = append(problems, fmt.Sprintf("unterminated quoted argument in %q", item))
				} else {
					d.Value, d.Quoted = unq, true
				}
			} else {
				d.Value = arg
				if arg == "" {
					problems = append(problems, fmt.Sprintf("directive %q has an equals sign but no argument", name))
				}
			}
		}
		dirs = append(dirs, d)
	}
	return dirs, problems
}

// Find returns the first directive with the given (lowercase) name.
func Find(dirs []Directive, name string) (Directive, bool) {
	for _, d := range dirs {
		if d.Name == name {
			return d, true
		}
	}
	return Directive{}, false
}

// splitList splits a comma-separated HTTP list, honoring quoted strings
// (a comma inside "…" does not separate elements).
func splitList(v string) []string {
	return splitQuoted(v, ',')
}

// splitQuoted splits v on sep outside quoted strings, preserving quotes
// and backslash escapes in the returned parts.
func splitQuoted(v string, sep byte) []string {
	var parts []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			b.WriteByte(c)
		case c == '\\' && inQuote && i+1 < len(v):
			b.WriteByte(c)
			i++
			b.WriteByte(v[i])
		case c == sep && !inQuote:
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	parts = append(parts, b.String())
	return parts
}
