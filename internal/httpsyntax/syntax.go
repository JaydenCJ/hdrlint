// Package httpsyntax implements the small pieces of RFC 9110 grammar that
// the rules need: tokens, field values, entity-tags, HTTP dates,
// Cache-Control directive lists, media types, and Set-Cookie lines. Every
// function is pure and total — invalid input yields a report, never a
// panic — because feeding hdrlint malformed headers is the whole point.
package httpsyntax

// IsToken reports whether s is a valid RFC 9110 §5.6.2 token
// (1*tchar). Header field names must be tokens (RFC 9110 §5.1).
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTChar(s[i]) {
			return false
		}
	}
	return true
}

// isTChar reports whether b is a tchar per RFC 9110 §5.6.2:
// "!#$%&'*+-.^_`|~" / DIGIT / ALPHA.
func isTChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// BadFieldValueByte scans a field value for bytes outside the RFC 9110
// §5.5 field-value grammar (VCHAR / SP / HTAB / obs-text). It returns the
// first offending byte and true, or 0 and false when the value is clean.
// CR and LF cannot appear here (line splitting removed them), but NUL and
// other control bytes survive and are the dangerous case the RFC calls out.
func BadFieldValueByte(s string) (byte, bool) {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == ' ' || b == '\t' {
			continue
		}
		if b >= 0x21 && b != 0x7F {
			// VCHAR (0x21–0x7E) and obs-text (0x80–0xFF).
			continue
		}
		return b, true
	}
	return 0, false
}

// ValidETag reports whether s is a valid entity-tag per RFC 9110 §8.8.3:
// an optional weakness prefix `W/` followed by a double-quoted opaque tag
// of etagc bytes (0x21 / 0x23–0x7E / obs-text — no embedded quotes).
func ValidETag(s string) bool {
	if len(s) >= 2 && s[0] == 'W' && s[1] == '/' {
		s = s[2:]
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		b := s[i]
		if b == 0x21 || (b >= 0x23 && b != 0x7F) {
			continue
		}
		return false
	}
	return true
}

// ParseDeltaSeconds parses an RFC 9111 §1.2.2 delta-seconds value
// (1*DIGIT). It returns the parsed value and true, or 0 and false for
// anything else — including negative numbers, floats, and empty strings.
// Values beyond 2^31-1 are capped there, as the RFC instructs.
func ParseDeltaSeconds(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < '0' || b > '9' {
			return 0, false
		}
		if n <= 1<<31 { // avoid overflow; cap per RFC 9111 §1.2.2
			n = n*10 + int64(b-'0')
		}
	}
	if n > 1<<31-1 {
		n = 1<<31 - 1
	}
	return n, true
}

// Unquote removes one layer of double quotes if present. The RFC 9110
// quoted-string escapes are resolved; a malformed quoted-string is
// returned as-is with ok=false.
func Unquote(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s, false
	}
	body := s[1 : len(s)-1]
	var out []byte
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' {
			if i == len(body)-1 {
				return s, false
			}
			i++
		}
		out = append(out, body[i])
	}
	return string(out), true
}
