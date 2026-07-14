// Unit tests for the RFC 9110 token / field-value / entity-tag grammar
// helpers. Edge cases mirror the ABNF exactly, since rules build on them.
package httpsyntax

import "testing"

func TestIsToken(t *testing.T) {
	for _, s := range []string{"Content-Type", "ETag", "max-age", "x", "A1!#$%&'*+-.^_`|~"} {
		if !IsToken(s) {
			t.Errorf("IsToken(%q) = false, want true", s)
		}
	}
	// Space, colon, quotes, and non-ASCII all break the token grammar;
	// empty is invalid because a token needs at least one tchar.
	for _, s := range []string{"", "Content Type", "name:", `"quoted"`, "naïve", "a,b", "a/b"} {
		if IsToken(s) {
			t.Errorf("IsToken(%q) = true, want false", s)
		}
	}
}

func TestBadFieldValueByte(t *testing.T) {
	cases := []struct {
		value string
		want  byte
	}{
		{"abc\x00def", 0x00},  // NUL is the classic injection byte
		{"abc\x01", 0x01},     // other C0 controls
		{"del\x7Fchar", 0x7F}, // DEL is excluded from VCHAR
		{"\x1b[31mred", 0x1b}, // ANSI escape smuggled into a header
	}
	for _, c := range cases {
		b, bad := BadFieldValueByte(c.value)
		if !bad || b != c.want {
			t.Errorf("BadFieldValueByte(%q) = (0x%02X, %v), want (0x%02X, true)", c.value, b, bad, c.want)
		}
	}
	// Visible ASCII, space, horizontal tab, and obs-text (0x80–0xFF)
	// are all grammatically legal field-value bytes.
	for _, s := range []string{"", "text/html; charset=utf-8", "a\tb", "caf\xc3\xa9", "!~"} {
		if b, bad := BadFieldValueByte(s); bad {
			t.Errorf("BadFieldValueByte(%q) flagged legal byte 0x%02X", s, b)
		}
	}
}

func TestValidETag(t *testing.T) {
	valid := []string{`"abc123"`, `W/"weak"`, `""`, `"!"`, `"33a64df551425fcc55e4d42a148795d9f25f89d4"`}
	for _, s := range valid {
		if !ValidETag(s) {
			t.Errorf("ValidETag(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"abc123",      // unquoted — the classic framework bug
		`W/abc`,       // weak prefix without quotes
		`"a"b"`,       // embedded quote
		`'single'`,    // wrong quote character
		`"has space"`, // SP is not an etagc
		`w/"weak"`,    // weakness prefix is case-sensitive: capital W only
		``,
	}
	for _, s := range invalid {
		if ValidETag(s) {
			t.Errorf("ValidETag(%q) = true, want false", s)
		}
	}
}

func TestParseDeltaSeconds(t *testing.T) {
	if n, ok := ParseDeltaSeconds("31536000"); !ok || n != 31536000 {
		t.Fatalf("ParseDeltaSeconds(31536000) = (%d, %v)", n, ok)
	}
	if n, ok := ParseDeltaSeconds("0"); !ok || n != 0 {
		t.Fatalf("ParseDeltaSeconds(0) = (%d, %v)", n, ok)
	}
	for _, s := range []string{"", "-1", "3.5", "60s", " 60", "1e3"} {
		if _, ok := ParseDeltaSeconds(s); ok {
			t.Errorf("ParseDeltaSeconds(%q) accepted invalid input", s)
		}
	}
	// RFC 9111 §1.2.2: values greater than 2^31-1 are treated as 2^31-1,
	// so a 100-digit max-age must not overflow into a negative number.
	n, ok := ParseDeltaSeconds("99999999999999999999999999999")
	if !ok || n != 1<<31-1 {
		t.Fatalf("huge delta-seconds = (%d, %v), want (%d, true)", n, ok, int64(1<<31-1))
	}
}

func TestUnquote(t *testing.T) {
	if s, ok := Unquote(`"hello"`); !ok || s != "hello" {
		t.Fatalf("Unquote basic = (%q, %v)", s, ok)
	}
	if s, ok := Unquote(`"a\"b"`); !ok || s != `a"b` {
		t.Fatalf("Unquote escaped = (%q, %v)", s, ok)
	}
	// Not quoted or malformed: returned as-is with ok=false.
	for _, s := range []string{"plain", `"unterminated`, `"trailing\"`, `"`} {
		if _, ok := Unquote(s); ok {
			t.Errorf("Unquote(%q) reported ok for malformed input", s)
		}
	}
}
