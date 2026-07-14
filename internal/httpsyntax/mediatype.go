package httpsyntax

import (
	"errors"
	"fmt"
	"strings"
)

// MediaType is a parsed Content-Type value per RFC 9110 §8.3.1.
type MediaType struct {
	// Type and Subtype are lowercased ("text", "html").
	Type    string
	Subtype string
	// Params holds parameters in order; names are lowercased.
	Params []MediaParam
}

// MediaParam is one media-type parameter (e.g. charset=utf-8).
type MediaParam struct {
	Name  string
	Value string
}

// Param returns the first parameter with the given lowercase name.
func (m MediaType) Param(name string) (string, bool) {
	for _, p := range m.Params {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// IsHTML reports whether the media type is an HTML document type, the
// gate for the browser-policy rules (CSP, frame protection, referrer).
func (m MediaType) IsHTML() bool {
	return (m.Type == "text" && m.Subtype == "html") ||
		(m.Type == "application" && m.Subtype == "xhtml+xml")
}

// ParseMediaType parses `type "/" subtype *( OWS ";" OWS parameter )` per
// RFC 9110 §8.3.1. Type, subtype, and parameter names must be tokens;
// parameter values may be tokens or quoted-strings.
func ParseMediaType(v string) (MediaType, error) {
	var mt MediaType
	parts := splitQuoted(v, ';')
	t, sub, ok := strings.Cut(strings.Trim(parts[0], " \t"), "/")
	if !ok {
		return mt, errors.New("missing '/' between type and subtype")
	}
	if !IsToken(t) {
		return mt, fmt.Errorf("type %q is not a valid token", t)
	}
	if !IsToken(sub) {
		return mt, fmt.Errorf("subtype %q is not a valid token", sub)
	}
	mt.Type, mt.Subtype = strings.ToLower(t), strings.ToLower(sub)
	for _, raw := range parts[1:] {
		raw = strings.Trim(raw, " \t")
		if raw == "" {
			return mt, errors.New("empty parameter (stray ';')")
		}
		name, val, has := strings.Cut(raw, "=")
		if !has {
			return mt, fmt.Errorf("parameter %q has no value", raw)
		}
		if !IsToken(name) {
			return mt, fmt.Errorf("parameter name %q is not a valid token", name)
		}
		if strings.HasPrefix(val, `"`) {
			unq, ok := Unquote(val)
			if !ok {
				return mt, fmt.Errorf("unterminated quoted value for parameter %q", name)
			}
			val = unq
		} else if !IsToken(val) {
			return mt, fmt.Errorf("parameter %q value %q is neither token nor quoted-string", name, val)
		}
		mt.Params = append(mt.Params, MediaParam{Name: strings.ToLower(name), Value: val})
	}
	return mt, nil
}
