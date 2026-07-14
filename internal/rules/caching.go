package rules

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/httpsyntax"
)

// knownCCDirective maps every response directive hdrlint recognizes to
// the spec defining it. RFC 9111 owns the core set; stale-* come from
// RFC 5861 and immutable from RFC 8246.
var knownCCDirective = map[string]bool{
	"max-age": true, "s-maxage": true, "no-cache": true, "no-store": true,
	"no-transform": true, "must-revalidate": true, "proxy-revalidate": true,
	"must-understand": true, "public": true, "private": true,
	"immutable": true, "stale-while-revalidate": true, "stale-if-error": true,
}

// requestOnlyCCDirective lists Cache-Control directives that are defined
// for requests only (RFC 9111 §5.2.1) and are meaningless in a response.
var requestOnlyCCDirective = map[string]bool{
	"max-stale": true, "min-fresh": true, "only-if-cached": true,
}

// storageGrantingCC lists directives that invite caches to store or serve
// the response — the direct contradiction of no-store.
var storageGrantingCC = []string{
	"max-age", "s-maxage", "public", "immutable",
	"stale-while-revalidate", "stale-if-error",
}

func cachingRules() []*Rule {
	return []*Rule{
		{
			ID: "cache-control-missing", Category: "caching", Severity: Info,
			Summary: "200 response without a Cache-Control header",
			Advice: "Without an explicit policy, caches fall back to heuristic freshness and every " +
				"intermediary guesses differently. State the intent, even if it is `no-store`.",
			Cite: RFC(9111, "5.2"),
			Check: func(t *Target) []string {
				if t.Resp.StatusCode == 200 && !t.Resp.Has("Cache-Control") {
					return []string{"200 response carries no Cache-Control; caches will apply heuristic freshness"}
				}
				return nil
			},
		},
		{
			ID: "cache-control-malformed", Category: "caching", Severity: Warn,
			Summary: "Cache-Control value violates the list grammar",
			Advice: "Empty list elements, non-token directive names, and unterminated quotes make " +
				"caches parse the policy differently — or drop it. Quoted delta-seconds arguments are " +
				"also flagged: senders SHOULD use the token form.",
			Cite: RFC(9111, "5.2"),
			Check: func(t *Target) []string {
				var out []string
				for _, v := range t.Resp.Values("Cache-Control") {
					dirs, problems := httpsyntax.ParseCacheControl(v)
					out = append(out, problems...)
					for _, d := range dirs {
						if d.Quoted && (d.Name == "max-age" || d.Name == "s-maxage") {
							out = append(out, fmt.Sprintf("%s uses the quoted-string form (%s=%q); senders should use the token form", d.Name, d.Name, d.Value))
						}
					}
				}
				return out
			},
		},
		{
			ID: "cache-no-store-conflict", Category: "caching", Severity: Error,
			Summary: "no-store combined with directives that grant caching",
			Advice: "no-store forbids storing the response at all, so pairing it with max-age, " +
				"s-maxage, public, immutable, or stale-* is a contradiction — and caches that only " +
				"honor one side of it will behave in whichever way you did not intend.",
			Cite: RFC(9111, "5.2.2.5"),
			Check: ccCheck(func(dirs []httpsyntax.Directive) []string {
				if _, ok := httpsyntax.Find(dirs, "no-store"); !ok {
					return nil
				}
				var conflicts []string
				for _, name := range storageGrantingCC {
					if _, ok := httpsyntax.Find(dirs, name); ok {
						conflicts = append(conflicts, name)
					}
				}
				if len(conflicts) > 0 {
					return []string{fmt.Sprintf("no-store contradicts %s in the same Cache-Control policy", strings.Join(conflicts, ", "))}
				}
				return nil
			}),
		},
		{
			ID: "cache-public-private", Category: "caching", Severity: Error,
			Summary: "Cache-Control sets both public and private",
			Advice: "public invites shared caches, private forbids them — a policy cannot do both. " +
				"Caches disagree on which wins; decide and send one.",
			Cite: RFC(9111, "5.2.2"),
			Check: ccCheck(func(dirs []httpsyntax.Directive) []string {
				_, pub := httpsyntax.Find(dirs, "public")
				_, priv := httpsyntax.Find(dirs, "private")
				if pub && priv {
					return []string{"Cache-Control declares both public and private; shared caches cannot honor both"}
				}
				return nil
			}),
		},
		{
			ID: "cache-private-smaxage", Category: "caching", Severity: Warn,
			Summary: "private combined with s-maxage",
			Advice: "s-maxage exists only for shared caches, which private excludes. One of the two " +
				"directives is dead weight and the pairing usually signals a copy-paste policy.",
			Cite: RFC(9111, "5.2.2.10"),
			Check: ccCheck(func(dirs []httpsyntax.Directive) []string {
				_, priv := httpsyntax.Find(dirs, "private")
				_, sma := httpsyntax.Find(dirs, "s-maxage")
				if priv && sma {
					return []string{"s-maxage targets shared caches but private forbids them from storing the response"}
				}
				return nil
			}),
		},
		{
			ID: "cache-invalid-max-age", Category: "caching", Severity: Error,
			Summary: "max-age or s-maxage argument is not a non-negative integer",
			Advice: "delta-seconds is 1*DIGIT: no sign, no units, no decimals. Caches receiving an " +
				"unparseable argument must treat the response as already stale, which is rarely the intent.",
			Cite: RFC(9111, "5.2.2.1"),
			Check: ccCheck(func(dirs []httpsyntax.Directive) []string {
				var out []string
				for _, d := range dirs {
					if d.Name != "max-age" && d.Name != "s-maxage" {
						continue
					}
					if !d.HasValue {
						out = append(out, fmt.Sprintf("%s has no argument; delta-seconds is required", d.Name))
						continue
					}
					if _, ok := httpsyntax.ParseDeltaSeconds(d.Value); !ok {
						out = append(out, fmt.Sprintf("%s=%q is not a non-negative integer; caches must treat the response as stale", d.Name, d.Value))
					}
				}
				return out
			}),
		},
		{
			ID: "cache-unknown-directive", Category: "caching", Severity: Info,
			Summary: "Unrecognized or request-only Cache-Control directive",
			Advice: "Extension directives are legal but ignored by caches that do not know them — " +
				"and in practice most unknown names are typos (no-chache, maxage). Request-only " +
				"directives such as only-if-cached have no defined meaning in responses.",
			Cite: RFC(9111, "5.2"),
			Check: ccCheck(func(dirs []httpsyntax.Directive) []string {
				var out []string
				for _, d := range dirs {
					if !httpsyntax.IsToken(d.Name) {
						continue // grammar errors belong to cache-control-malformed
					}
					switch {
					case knownCCDirective[d.Name]:
					case requestOnlyCCDirective[d.Name]:
						out = append(out, fmt.Sprintf("%s is a request directive with no defined meaning in a response", d.Name))
					default:
						out = append(out, fmt.Sprintf("unknown directive %q; extensions are legal but this is often a typo", d.Name))
					}
				}
				return out
			}),
		},
		{
			ID: "expires-invalid", Category: "caching", Severity: Warn,
			Summary: "Expires is not a valid HTTP-date",
			Advice: "Caches must treat an unparseable Expires as already expired. `Expires: 0` is a " +
				"widespread idiom that works only by being invalid — prefer `Cache-Control: no-cache`.",
			Cite: RFC(9111, "5.3"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Expires")
				if !ok {
					return nil
				}
				if _, f := httpsyntax.ParseHTTPDate(v); f == httpsyntax.DateInvalid {
					return []string{fmt.Sprintf("Expires value %q is not a valid HTTP-date; caches treat it as already expired", v)}
				}
				return nil
			},
		},
		{
			ID: "expires-ignored", Category: "caching", Severity: Info,
			Summary: "Expires is overridden by Cache-Control max-age",
			Advice: "When max-age (or s-maxage) is present, recipients must ignore Expires. Keeping " +
				"both invites drift: the two freshness lifetimes silently disagree over time.",
			Cite: RFC(9111, "5.3"),
			Check: func(t *Target) []string {
				if !t.Resp.Has("Expires") {
					return nil
				}
				for _, v := range t.Resp.Values("Cache-Control") {
					dirs, _ := httpsyntax.ParseCacheControl(v)
					if _, ok := httpsyntax.Find(dirs, "max-age"); ok {
						return []string{"Expires is present but Cache-Control max-age wins; recipients must ignore Expires"}
					}
					if _, ok := httpsyntax.Find(dirs, "s-maxage"); ok {
						return []string{"Expires is present but Cache-Control s-maxage wins in shared caches"}
					}
				}
				return nil
			},
		},
		{
			ID: "pragma-response", Category: "caching", Severity: Info,
			Summary: "Pragma has no meaning in responses and is deprecated",
			Advice: "Pragma was defined for requests, only ever meant HTTP/1.0 `no-cache`, and is " +
				"deprecated. In a response it does nothing; say it with Cache-Control instead.",
			Cite: RFC(9111, "5.4"),
			Check: func(t *Target) []string {
				if v, ok := t.Resp.Get("Pragma"); ok {
					return []string{fmt.Sprintf("Pragma: %s is deprecated and has no defined semantics in a response", v)}
				}
				return nil
			},
		},
		{
			ID: "age-invalid", Category: "caching", Severity: Warn,
			Summary: "Age is not a non-negative integer",
			Advice: "Age carries delta-seconds spent in caches. A non-integer value makes freshness " +
				"math undefined; recipients are told to replace unparseable Age with 0 or treat the " +
				"response as stale, and implementations differ.",
			Cite: RFC(9111, "5.1"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Age")
				if !ok {
					return nil
				}
				if _, valid := httpsyntax.ParseDeltaSeconds(strings.Trim(v, " \t")); !valid {
					return []string{fmt.Sprintf("Age value %q is not a non-negative integer", v)}
				}
				return nil
			},
		},
		{
			ID: "vary-wildcard", Category: "caching", Severity: Warn,
			Summary: "Vary: * makes the response effectively uncacheable",
			Advice: "A * member tells caches that unspecified request parts affect the response, so " +
				"no stored copy can ever be reused without revalidation. If that is the intent, " +
				"`Cache-Control: no-store` says it honestly; otherwise list the real request headers.",
			Cite: RFC(9110, "12.5.5"),
			Check: func(t *Target) []string {
				var members []string
				for _, v := range t.Resp.Values("Vary") {
					for _, m := range strings.Split(v, ",") {
						members = append(members, strings.Trim(m, " \t"))
					}
				}
				for _, m := range members {
					if m == "*" {
						msg := "Vary: * forbids caches from reusing any stored copy"
						if len(members) > 1 {
							msg += " (the other listed members are moot)"
						}
						return []string{msg}
					}
				}
				return nil
			},
		},
		{
			ID: "etag-malformed", Category: "caching", Severity: Error,
			Summary: "ETag is not a valid entity-tag",
			Advice: "An entity-tag is an optionally W/-prefixed double-quoted string. Unquoted ETags " +
				"(a common framework bug) break If-None-Match comparison at strict caches and CDNs, " +
				"silently disabling conditional revalidation.",
			Cite: RFC(9110, "8.8.3"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("ETag")
				if !ok {
					return nil
				}
				if !httpsyntax.ValidETag(v) {
					return []string{fmt.Sprintf("ETag value %s is not a valid entity-tag (must be a quoted string, optionally W/-prefixed)", v)}
				}
				return nil
			},
		},
		{
			ID: "last-modified-future", Category: "caching", Severity: Warn,
			Summary: "Last-Modified is later than the Date header",
			Advice: "A resource cannot have been modified after the response was generated; origin " +
				"servers should replace such a timestamp with Date. Future dates skew heuristic " +
				"freshness and make conditional requests misfire.",
			Cite: RFC(9110, "8.8.2"),
			Check: func(t *Target) []string {
				lmv, ok1 := t.Resp.Get("Last-Modified")
				dv, ok2 := t.Resp.Get("Date")
				if !ok1 || !ok2 {
					return nil
				}
				lm, f1 := httpsyntax.ParseHTTPDate(lmv)
				d, f2 := httpsyntax.ParseHTTPDate(dv)
				if f1 != httpsyntax.DateInvalid && f2 != httpsyntax.DateInvalid && lm.After(d) {
					return []string{fmt.Sprintf("Last-Modified (%s) is after Date (%s)", lmv, dv)}
				}
				return nil
			},
		},
	}
}

// ccCheck parses every Cache-Control field once and hands the combined
// directive list to the rule body.
func ccCheck(f func([]httpsyntax.Directive) []string) func(*Target) []string {
	return func(t *Target) []string {
		values := t.Resp.Values("Cache-Control")
		if len(values) == 0 {
			return nil
		}
		var dirs []httpsyntax.Directive
		for _, v := range values {
			d, _ := httpsyntax.ParseCacheControl(v)
			dirs = append(dirs, d...)
		}
		return f(dirs)
	}
}
