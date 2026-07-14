// Tests for the Cache-Control directive-list parser.
package httpsyntax

import "testing"

func TestParseCacheControlBasicDirectives(t *testing.T) {
	dirs, problems := ParseCacheControl("public, max-age=600, must-revalidate")
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(dirs) != 3 {
		t.Fatalf("got %d directives, want 3", len(dirs))
	}
	ma, ok := Find(dirs, "max-age")
	if !ok || !ma.HasValue || ma.Value != "600" || ma.Quoted {
		t.Fatalf("max-age parsed as %+v", ma)
	}
	if _, ok := Find(dirs, "public"); !ok {
		t.Fatal("public directive missing")
	}
}

func TestParseCacheControlNamesAreCaseInsensitive(t *testing.T) {
	// RFC 9111 §5.2: directive names are case-insensitive; the parser
	// lowercases so Find works with canonical names.
	dirs, _ := ParseCacheControl("Max-Age=60, NO-STORE")
	if _, ok := Find(dirs, "max-age"); !ok {
		t.Error("Max-Age not found as max-age")
	}
	if _, ok := Find(dirs, "no-store"); !ok {
		t.Error("NO-STORE not found as no-store")
	}
}

func TestParseCacheControlQuotedArgumentWithComma(t *testing.T) {
	// The comma inside the quoted string must not split the list —
	// this is the canonical private="set-cookie, authorization" shape.
	dirs, problems := ParseCacheControl(`private="set-cookie, authorization", max-age=0`)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(dirs) != 2 {
		t.Fatalf("got %d directives, want 2 (quoted comma split the list)", len(dirs))
	}
	priv, _ := Find(dirs, "private")
	if !priv.Quoted || priv.Value != "set-cookie, authorization" {
		t.Fatalf("private parsed as %+v", priv)
	}
}

func TestParseCacheControlReportsProblems(t *testing.T) {
	// "max-age=60,,no-cache" and trailing commas are sender violations
	// of the list grammar (RFC 9110 §5.6.1).
	_, problems := ParseCacheControl("max-age=60,,no-cache")
	if len(problems) != 1 {
		t.Fatalf("doubled comma: got problems %v, want exactly one", problems)
	}
	_, problems = ParseCacheControl("no-store,")
	if len(problems) != 1 {
		t.Fatalf("trailing comma: got problems %v, want exactly one", problems)
	}
	_, problems = ParseCacheControl("max age=60")
	if len(problems) == 0 {
		t.Error("space in directive name not reported")
	}
	_, problems = ParseCacheControl(`private="unterminated`)
	if len(problems) == 0 {
		t.Error("unterminated quote not reported")
	}
	_, problems = ParseCacheControl("max-age=")
	if len(problems) == 0 {
		t.Error("equals sign with empty argument not reported")
	}
}
