// Tests for the Set-Cookie parser.
package httpsyntax

import "testing"

func TestParseSetCookieBasic(t *testing.T) {
	c, err := ParseSetCookie("session=abc123; Path=/; Secure; HttpOnly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name != "session" || c.Value != "abc123" {
		t.Fatalf("cookie-pair parsed as %q=%q", c.Name, c.Value)
	}
	if !c.HasAttr("Secure") || !c.HasAttr("HttpOnly") {
		t.Fatal("boolean attributes missing")
	}
	if p, _ := c.Attr("Path"); p != "/" {
		t.Fatalf("Path = %q", p)
	}
	// Base64 cookie values routinely end in '='; only the first '='
	// separates name from value.
	c, err = ParseSetCookie("token=eyJhbGciOiJIUzI1NiJ9==; Path=/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Value != "eyJhbGciOiJIUzI1NiJ9==" {
		t.Fatalf("value = %q", c.Value)
	}
}

func TestParseSetCookieAttributesAreCaseInsensitive(t *testing.T) {
	// RFC 6265 §5.2 matches attribute names case-insensitively;
	// "secure" and "SECURE" are the same attribute.
	c, err := ParseSetCookie("id=1; secure; SAMESITE=none")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasAttr("Secure") {
		t.Error("lowercase secure not matched")
	}
	if ss, ok := c.Attr("SameSite"); !ok || ss != "none" {
		t.Errorf("SameSite = (%q, %v)", ss, ok)
	}
}

func TestParseSetCookieRequiresNameValuePair(t *testing.T) {
	for _, s := range []string{"", "noequals", "=valueonly; Path=/"} {
		if _, err := ParseSetCookie(s); err == nil {
			t.Errorf("ParseSetCookie(%q) succeeded, want error", s)
		}
	}
}
