// Tests for the RFC 9110 §8.3.1 media-type parser.
package httpsyntax

import "testing"

func TestParseMediaTypeSimple(t *testing.T) {
	mt, err := ParseMediaType("text/html")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mt.Type != "text" || mt.Subtype != "html" || len(mt.Params) != 0 {
		t.Fatalf("parsed %+v", mt)
	}
}

func TestParseMediaTypeLowercasesAndParsesParams(t *testing.T) {
	mt, err := ParseMediaType(`Text/HTML; Charset=UTF-8; boundary="a;b"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mt.Type != "text" || mt.Subtype != "html" {
		t.Fatalf("type/subtype not lowercased: %+v", mt)
	}
	if cs, ok := mt.Param("charset"); !ok || cs != "UTF-8" {
		t.Fatalf("charset param = (%q, %v)", cs, ok)
	}
	// A ';' inside a quoted parameter value must not split parameters.
	if b, ok := mt.Param("boundary"); !ok || b != "a;b" {
		t.Fatalf("boundary param = (%q, %v), want (\"a;b\", true)", b, ok)
	}
}

func TestParseMediaTypeErrors(t *testing.T) {
	for _, s := range []string{
		"texthtml",        // no slash
		"text/",           // empty subtype
		"/html",           // empty type
		"te xt/html",      // space in type token
		"text/html; a",    // parameter without value
		"text/html; =b",   // parameter without name
		`text/html; a="x`, // unterminated quote
		"text/html;",      // stray semicolon
	} {
		if _, err := ParseMediaType(s); err == nil {
			t.Errorf("ParseMediaType(%q) succeeded, want error", s)
		}
	}
}

func TestMediaTypeIsHTML(t *testing.T) {
	html, _ := ParseMediaType("text/html; charset=utf-8")
	xhtml, _ := ParseMediaType("application/xhtml+xml")
	plain, _ := ParseMediaType("text/plain")
	if !html.IsHTML() || !xhtml.IsHTML() {
		t.Error("HTML media types not recognized")
	}
	if plain.IsHTML() {
		t.Error("text/plain misidentified as HTML")
	}
}
