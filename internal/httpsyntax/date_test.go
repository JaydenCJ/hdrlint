// Tests for HTTP-date parsing across the three RFC 9110 §5.6.7 grammars.
package httpsyntax

import (
	"testing"
	"time"
)

func TestParseHTTPDateIMFFixdate(t *testing.T) {
	got, f := ParseHTTPDate("Sun, 06 Nov 1994 08:49:37 GMT")
	if f != DateIMF {
		t.Fatalf("format = %v, want IMF", f)
	}
	want := time.Date(1994, 11, 6, 8, 49, 37, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
}

func TestParseHTTPDateObsoleteForms(t *testing.T) {
	// Recipients must still accept RFC 850 and asctime, and hdrlint must
	// know which form was used so it can flag the obsolete ones.
	if _, f := ParseHTTPDate("Sunday, 06-Nov-94 08:49:37 GMT"); f != DateRFC850 {
		t.Errorf("RFC 850 form detected as %v", f)
	}
	if _, f := ParseHTTPDate("Sun Nov  6 08:49:37 1994"); f != DateAsctime {
		t.Errorf("asctime form detected as %v", f)
	}
	// Format names feed directly into finding messages.
	names := map[DateFormat]string{
		DateIMF:     "IMF-fixdate",
		DateRFC850:  "obsolete RFC 850 date",
		DateAsctime: "obsolete asctime date",
		DateInvalid: "invalid",
	}
	for f, want := range names {
		if f.String() != want {
			t.Errorf("%d.String() = %q, want %q", f, f.String(), want)
		}
	}
}

func TestParseHTTPDateRejectsNonHTTPFormats(t *testing.T) {
	// The formats servers actually emit when they get this wrong:
	// ISO 8601, epoch seconds, "0", localized strings.
	for _, s := range []string{
		"2026-07-11T12:00:00Z",
		"1752235200",
		"0",
		"-1",
		"Sat, 11 Jul 2026 12:00:00 UTC", // wrong zone name: must be GMT
		"",
	} {
		if _, f := ParseHTTPDate(s); f != DateInvalid {
			t.Errorf("ParseHTTPDate(%q) = %v, want invalid", s, f)
		}
	}
}
