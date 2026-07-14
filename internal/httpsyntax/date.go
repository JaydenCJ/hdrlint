package httpsyntax

import "time"

// DateFormat identifies which of the three HTTP-date shapes a timestamp
// used. RFC 9110 §5.6.7 obliges senders to generate IMF-fixdate and
// recipients to also accept the two obsolete forms.
type DateFormat int

const (
	// DateInvalid means the string parsed as none of the three forms.
	DateInvalid DateFormat = iota
	// DateIMF is IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT".
	DateIMF
	// DateRFC850 is the obsolete RFC 850 form: "Sunday, 06-Nov-94 08:49:37 GMT".
	DateRFC850
	// DateAsctime is the obsolete asctime() form: "Sun Nov  6 08:49:37 1994".
	DateAsctime
)

// String names the format for report messages.
func (f DateFormat) String() string {
	switch f {
	case DateIMF:
		return "IMF-fixdate"
	case DateRFC850:
		return "obsolete RFC 850 date"
	case DateAsctime:
		return "obsolete asctime date"
	default:
		return "invalid"
	}
}

// dateLayouts pairs each accepted layout with its format tag, in the
// order RFC 9110 lists them.
var dateLayouts = []struct {
	layout string
	format DateFormat
}{
	{"Mon, 02 Jan 2006 15:04:05 GMT", DateIMF},
	{"Monday, 02-Jan-06 15:04:05 GMT", DateRFC850},
	{"Mon Jan _2 15:04:05 2006", DateAsctime},
}

// ParseHTTPDate parses an HTTP-date per RFC 9110 §5.6.7, reporting which
// of the three grammars matched so rules can flag the obsolete ones.
func ParseHTTPDate(s string) (time.Time, DateFormat) {
	for _, dl := range dateLayouts {
		if t, err := time.Parse(dl.layout, s); err == nil {
			return t, dl.format
		}
	}
	return time.Time{}, DateInvalid
}
