package rules

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/httpsyntax"
)

// citeHTMLCharset covers the charset advice, which lives in the WHATWG
// HTML standard rather than an RFC.
var citeHTMLCharset = Citation{
	Spec: "WHATWG HTML",
	URL:  "https://html.spec.whatwg.org/multipage/semantics.html#charset",
}

// singletonFields must not appear more than once in a message: each is
// defined as a single value, not a comma-separated list (RFC 9110 §5.3).
var singletonFields = []string{
	"Age", "Content-Length", "Content-Location", "Content-Range",
	"Content-Type", "Date", "ETag", "Expires", "Last-Modified",
	"Location", "Retry-After", "Server",
}

// redirectStatuses are the 3xx codes for which Location carries the
// redirect target.
var redirectStatuses = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

func correctnessRules() []*Rule {
	return []*Rule{
		{
			ID: "duplicate-singleton", Category: "correctness", Severity: Error,
			Summary: "A singleton header appears more than once",
			Advice: "Fields like Content-Type or Date are defined as single values, so a message " +
				"may contain at most one. Recipients pick first or last inconsistently — classic " +
				"ground for cache poisoning and framing disagreements between proxy layers.",
			Cite: RFC(9110, "5.3"),
			Check: func(t *Target) []string {
				var out []string
				for _, name := range singletonFields {
					vals := t.Resp.Values(name)
					if len(vals) < 2 {
						continue
					}
					identical := true
					for _, v := range vals[1:] {
						if v != vals[0] {
							identical = false
							break
						}
					}
					detail := "with differing values"
					if identical {
						detail = "with identical values"
					}
					out = append(out, fmt.Sprintf("%s appears %d times %s; it is a singleton field", name, len(vals), detail))
				}
				return out
			},
		},
		{
			ID: "content-length-transfer-encoding", Category: "correctness", Severity: Error,
			Summary: "Content-Length and Transfer-Encoding sent together",
			Advice: "When both framing mechanisms are present, front-end and back-end servers can " +
				"disagree about where the message ends — the root of request-smuggling attacks. " +
				"Send exactly one.",
			Cite: RFC(9112, "6.3"),
			Check: func(t *Target) []string {
				if t.Resp.Has("Content-Length") && t.Resp.Has("Transfer-Encoding") {
					return []string{"Content-Length and Transfer-Encoding are both present; ambiguous framing enables smuggling attacks"}
				}
				return nil
			},
		},
		{
			ID: "content-length-invalid", Category: "correctness", Severity: Error,
			Summary: "Content-Length is not a valid length",
			Advice: "The grammar is 1*DIGIT. Signs, decimals, units, and comma-joined lists (the " +
				"residue of duplicate headers) all make message framing undefined.",
			Cite: RFC(9110, "8.6"),
			Check: func(t *Target) []string {
				var out []string
				for _, v := range t.Resp.Values("Content-Length") {
					if _, ok := httpsyntax.ParseDeltaSeconds(strings.Trim(v, " \t")); !ok {
						out = append(out, fmt.Sprintf("Content-Length value %q is not a sequence of digits", v))
					}
				}
				return out
			},
		},
		{
			ID: "content-length-status", Category: "correctness", Severity: Error,
			Summary: "Content-Length on a 1xx or 204 response",
			Advice: "A server must not send Content-Length in 1xx or 204 responses; these statuses " +
				"never carry content, and a stray length desynchronizes connection reuse.",
			Cite: RFC(9110, "8.6"),
			Check: func(t *Target) []string {
				code := t.Resp.StatusCode
				if (code == 204 || (code >= 100 && code < 200)) && t.Resp.Has("Content-Length") {
					return []string{fmt.Sprintf("Content-Length must not be sent with status %d", code)}
				}
				return nil
			},
		},
		{
			ID: "content-type-missing", Category: "correctness", Severity: Warn,
			Summary: "Response with content but no Content-Type",
			Advice: "Without a declared type, recipients guess — and browsers sniff, which is " +
				"exactly what nosniff exists to prevent. If the type is truly unknown, " +
				"`application/octet-stream` states that explicitly.",
			Cite: RFC(9110, "8.3"),
			Check: func(t *Target) []string {
				if t.Resp.StatusCode == 0 || bodylessStatus(t.Resp.StatusCode) {
					return nil
				}
				if cl, ok := t.Resp.Get("Content-Length"); ok && strings.Trim(cl, " \t") == "0" {
					return nil
				}
				if !t.Resp.Has("Content-Type") {
					return []string{"response carries content but no Content-Type; recipients will guess or sniff"}
				}
				return nil
			},
		},
		{
			ID: "content-type-malformed", Category: "correctness", Severity: Error,
			Summary: "Content-Type is not a valid media type",
			Advice: "The value must be `type/subtype` with optional `;name=value` parameters, all " +
				"tokens or quoted-strings. Malformed types are dropped or guessed at by recipients.",
			Cite: RFC(9110, "8.3.1"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Content-Type")
				if !ok {
					return nil
				}
				if _, err := httpsyntax.ParseMediaType(v); err != nil {
					return []string{fmt.Sprintf("Content-Type %q is malformed: %s", v, err)}
				}
				return nil
			},
		},
		{
			ID: "charset-missing", Category: "correctness", Severity: Info,
			Summary: "text/html without an explicit charset",
			Advice: "HTML defaults to UTF-8 in browsers, but proxies, scrapers, and older tooling " +
				"still mis-decode unlabeled documents. `text/html; charset=utf-8` costs 15 bytes.",
			Cite: citeHTMLCharset,
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Content-Type")
				if !ok {
					return nil
				}
				mt, err := httpsyntax.ParseMediaType(v)
				if err != nil || !(mt.Type == "text" && mt.Subtype == "html") {
					return nil
				}
				if _, has := mt.Param("charset"); !has {
					return []string{"text/html response does not declare a charset; add `; charset=utf-8`"}
				}
				return nil
			},
		},
		{
			ID: "date-missing", Category: "correctness", Severity: Warn,
			Summary: "Response without a Date header",
			Advice: "Origin servers with a clock must send Date on all non-1xx/5xx responses; " +
				"caches otherwise substitute their own receive time, skewing every age calculation.",
			Cite: RFC(9110, "6.6.1"),
			Check: func(t *Target) []string {
				code := t.Resp.StatusCode
				if code >= 200 && code < 500 && !t.Resp.Has("Date") {
					return []string{"no Date header; caches will substitute their own clock for freshness math"}
				}
				return nil
			},
		},
		{
			ID: "date-invalid", Category: "correctness", Severity: Error,
			Summary: "Date or Last-Modified is not a valid HTTP-date",
			Advice: "HTTP-dates must parse as IMF-fixdate (or the two obsolete forms recipients " +
				"still accept). Anything else — ISO 8601, epoch seconds, localized strings — is " +
				"invalid and breaks caching and conditional requests.",
			Cite: RFC(9110, "5.6.7"),
			Check: func(t *Target) []string {
				var out []string
				for _, name := range []string{"Date", "Last-Modified"} {
					v, ok := t.Resp.Get(name)
					if !ok {
						continue
					}
					if _, f := httpsyntax.ParseHTTPDate(v); f == httpsyntax.DateInvalid {
						out = append(out, fmt.Sprintf("%s value %q is not a valid HTTP-date", name, v))
					}
				}
				return out
			},
		},
		{
			ID: "date-obsolete-format", Category: "correctness", Severity: Warn,
			Summary: "Timestamp uses an obsolete HTTP-date form",
			Advice: "Senders must generate IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`). The RFC " +
				"850 and asctime forms are accepted for legacy reasons only, and two-digit years " +
				"are guessed at by recipients.",
			Cite: RFC(9110, "5.6.7"),
			Check: func(t *Target) []string {
				var out []string
				for _, name := range []string{"Date", "Expires", "Last-Modified"} {
					v, ok := t.Resp.Get(name)
					if !ok {
						continue
					}
					if _, f := httpsyntax.ParseHTTPDate(v); f == httpsyntax.DateRFC850 || f == httpsyntax.DateAsctime {
						out = append(out, fmt.Sprintf("%s uses the %s form; senders must generate IMF-fixdate", name, f))
					}
				}
				return out
			},
		},
		{
			ID: "redirect-location-missing", Category: "correctness", Severity: Warn,
			Summary: "Redirect status without a Location header",
			Advice: "3xx responses should carry the redirect target in Location; without it, " +
				"clients have nowhere to go and most render an empty page or an error.",
			Cite: RFC(9110, "15.4"),
			Check: func(t *Target) []string {
				if redirectStatuses[t.Resp.StatusCode] && !t.Resp.Has("Location") {
					return []string{fmt.Sprintf("status %d is a redirect but no Location header is present", t.Resp.StatusCode)}
				}
				return nil
			},
		},
		{
			ID: "allow-missing-405", Category: "correctness", Severity: Error,
			Summary: "405 response without an Allow header",
			Advice: "A 405 must tell the client which methods the resource does support, via Allow. " +
				"Omitting it is a MUST-level violation and leaves clients probing blindly.",
			Cite: RFC(9110, "15.5.6"),
			Check: func(t *Target) []string {
				if t.Resp.StatusCode == 405 && !t.Resp.Has("Allow") {
					return []string{"405 Method Not Allowed must include an Allow header listing the supported methods"}
				}
				return nil
			},
		},
		{
			ID: "retry-after-invalid", Category: "correctness", Severity: Warn,
			Summary: "Retry-After is neither delta-seconds nor an HTTP-date",
			Advice: "Retry-After takes seconds (`120`) or an HTTP-date. Well-behaved clients and " +
				"crawlers honor it; an unparseable value forfeits that backoff for free.",
			Cite: RFC(9110, "10.2.3"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Retry-After")
				if !ok {
					return nil
				}
				trimmed := strings.Trim(v, " \t")
				if _, isNum := httpsyntax.ParseDeltaSeconds(trimmed); isNum {
					return nil
				}
				if _, f := httpsyntax.ParseHTTPDate(trimmed); f != httpsyntax.DateInvalid {
					return nil
				}
				return []string{fmt.Sprintf("Retry-After value %q is neither delta-seconds nor an HTTP-date", v)}
			},
		},
		{
			ID: "field-name-invalid", Category: "correctness", Severity: Error,
			Summary: "Header field name is not a valid token",
			Advice: "Field names are tokens: no spaces, no colons, only tchar bytes. A space before " +
				"the colon or a non-ASCII name makes intermediaries reject or — worse — re-interpret " +
				"the line.",
			Cite: RFC(9110, "5.1"),
			Check: func(t *Target) []string {
				var out []string
				for _, f := range t.Resp.Fields {
					if f.NoColon {
						out = append(out, fmt.Sprintf("line %q has no colon and is not a header field", truncate(f.Name, 60)))
						continue
					}
					if !httpsyntax.IsToken(f.Name) {
						out = append(out, fmt.Sprintf("field name %q is not a valid token", f.Name))
					}
				}
				return out
			},
		},
		{
			ID: "field-value-invalid", Category: "correctness", Severity: Error,
			Summary: "Header field value contains a forbidden byte",
			Advice: "Field values may contain visible ASCII, space, and tab. NUL and other control " +
				"bytes are invalid and dangerous — several header-injection exploits ride on them.",
			Cite: RFC(9110, "5.5"),
			Check: func(t *Target) []string {
				var out []string
				for _, f := range t.Resp.Fields {
					if f.NoColon {
						continue
					}
					if b, bad := httpsyntax.BadFieldValueByte(f.Value); bad {
						out = append(out, fmt.Sprintf("value of %s contains forbidden byte 0x%02X", f.Name, b))
					}
				}
				return out
			},
		},
		{
			ID: "obs-fold", Category: "correctness", Severity: Error,
			Summary: "Header value uses obsolete line folding",
			Advice: "Continuing a field value onto the next line with leading whitespace (obs-fold) " +
				"must not be generated; parsers disagree about it, which again means smuggling risk.",
			Cite: RFC(9112, "5.2"),
			Check: func(t *Target) []string {
				var out []string
				for _, f := range t.Resp.Fields {
					if f.ObsFolded {
						out = append(out, fmt.Sprintf("value of %s is folded across multiple lines (obs-fold); senders must not generate this", f.Name))
					}
				}
				return out
			},
		},
	}
}

// truncate shortens s for display in a finding message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
