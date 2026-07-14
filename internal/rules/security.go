package rules

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/httpsyntax"
)

// Non-RFC citations used by the security rules. Browser-era headers are
// governed by WHATWG/W3C living standards; where not even those apply
// (pure hygiene), the OWASP Secure Headers Project is cited.
var (
	citeCSP3 = Citation{
		Spec: "W3C CSP3",
		URL:  "https://www.w3.org/TR/CSP3/",
	}
	citeFetchNosniff = Citation{
		Spec: "WHATWG Fetch",
		URL:  "https://fetch.spec.whatwg.org/#x-content-type-options-header",
	}
	citeFetchCORS = Citation{
		Spec: "WHATWG Fetch",
		URL:  "https://fetch.spec.whatwg.org/#cors-protocol-and-credentials",
	}
	citeReferrerPolicy = Citation{
		Spec: "W3C Referrer Policy",
		URL:  "https://www.w3.org/TR/referrer-policy/",
	}
	citeOWASPHeaders = Citation{
		Spec: "OWASP Secure Headers",
		URL:  "https://owasp.org/www-project-secure-headers/",
	}
	cite6265bis = Citation{
		Spec:    "RFC 6265bis",
		Section: "4.1.2.7",
		URL:     "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.2.7",
	}
)

// hstsShortMaxAge is the threshold below which an HSTS policy is
// considered too short to be protective: 180 days.
const hstsShortMaxAge = 15552000

func securityRules() []*Rule {
	return []*Rule{
		{
			ID: "hsts-missing", Category: "security", Severity: Warn, HTTPSOnly: true,
			Summary: "HTTPS response without Strict-Transport-Security",
			Advice: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every " +
				"HTTPS response so browsers refuse downgraded plaintext connections for the whole host.",
			Cite: RFC(6797, "7.1"),
			Check: func(t *Target) []string {
				if !t.Resp.Has("Strict-Transport-Security") {
					return []string{"Strict-Transport-Security is not set on an HTTPS response"}
				}
				return nil
			},
		},
		{
			ID: "hsts-malformed", Category: "security", Severity: Error,
			Summary: "Strict-Transport-Security value violates the RFC 6797 grammar",
			Advice: "The header must contain a `max-age=<delta-seconds>` directive; directive names " +
				"must be tokens. A malformed policy is ignored by browsers, silently disabling HSTS.",
			Cite: RFC(6797, "6.1"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Strict-Transport-Security")
				if !ok {
					return nil
				}
				return checkHSTSSyntax(v)
			},
		},
		{
			ID: "hsts-short-max-age", Category: "security", Severity: Warn,
			Summary: "HSTS max-age below 180 days",
			Advice: "Short policies expire between visits and leave the first request unprotected " +
				"again. Use at least 15552000 (180 days); 31536000 is required for preload lists.",
			Cite: RFC(6797, "6.1.1"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Strict-Transport-Security")
				if !ok {
					return nil
				}
				secs, ok := hstsMaxAge(v)
				if ok && secs < hstsShortMaxAge {
					return []string{fmt.Sprintf("HSTS max-age is %d seconds (less than 180 days)", secs)}
				}
				return nil
			},
		},
		{
			ID: "hsts-over-http", Category: "security", Severity: Warn, HTTPOnly: true,
			Summary: "Strict-Transport-Security sent over plain HTTP",
			Advice: "RFC 6797 forbids sending the STS header over non-secure transport and requires " +
				"browsers to ignore it there. Redirect to HTTPS first, then set the policy.",
			Cite: RFC(6797, "7.2"),
			Check: func(t *Target) []string {
				if t.Resp.Has("Strict-Transport-Security") {
					return []string{"Strict-Transport-Security has no effect over plain HTTP and must be ignored by clients"}
				}
				return nil
			},
		},
		{
			ID: "nosniff-missing", Category: "security", Severity: Warn,
			Summary: "X-Content-Type-Options: nosniff is absent",
			Advice: "Without `nosniff`, browsers may MIME-sniff responses into executable types, " +
				"turning an innocent upload endpoint into an XSS vector. Send it on every response.",
			Cite: citeFetchNosniff,
			Check: func(t *Target) []string {
				if bodylessStatus(t.Resp.StatusCode) {
					return nil
				}
				if !t.Resp.Has("X-Content-Type-Options") {
					return []string{"X-Content-Type-Options is not set (browsers may MIME-sniff the body)"}
				}
				return nil
			},
		},
		{
			ID: "nosniff-invalid", Category: "security", Severity: Warn,
			Summary: "X-Content-Type-Options has a value other than nosniff",
			Advice: "The only defined value is `nosniff`; anything else fails the Fetch algorithm's " +
				"check and the protection silently does not apply.",
			Cite: citeFetchNosniff,
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("X-Content-Type-Options")
				if !ok {
					return nil
				}
				first := strings.Trim(strings.SplitN(v, ",", 2)[0], " \t")
				if !strings.EqualFold(first, "nosniff") {
					return []string{fmt.Sprintf("X-Content-Type-Options value %q is not \"nosniff\"; sniffing protection does not engage", v)}
				}
				return nil
			},
		},
		{
			ID: "frame-protection-missing", Category: "security", Severity: Info,
			Summary: "HTML response with neither frame-ancestors nor X-Frame-Options",
			Advice: "Pages that never expect to be framed should send " +
				"`Content-Security-Policy: frame-ancestors 'none'` (or X-Frame-Options: DENY for " +
				"legacy browsers) to rule out clickjacking overlays.",
			Cite: RFC(7034, "2.1"),
			Check: func(t *Target) []string {
				if !isHTML(t) {
					return nil
				}
				if t.Resp.Has("X-Frame-Options") {
					return nil
				}
				if csp, ok := t.Resp.Get("Content-Security-Policy"); ok && cspHasDirective(csp, "frame-ancestors") {
					return nil
				}
				return []string{"HTML response has neither CSP frame-ancestors nor X-Frame-Options (clickjacking is possible)"}
			},
		},
		{
			ID: "xfo-invalid", Category: "security", Severity: Warn,
			Summary: "X-Frame-Options value is not DENY or SAMEORIGIN",
			Advice: "Only DENY and SAMEORIGIN are interoperable; ALLOW-FROM was never widely " +
				"implemented and is treated as an invalid value (ignored) by modern browsers. " +
				"Use CSP frame-ancestors for allow-listing.",
			Cite: RFC(7034, "2.1"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("X-Frame-Options")
				if !ok {
					return nil
				}
				upper := strings.ToUpper(strings.Trim(v, " \t"))
				switch {
				case upper == "DENY" || upper == "SAMEORIGIN":
					return nil
				case strings.HasPrefix(upper, "ALLOW-FROM"):
					return []string{fmt.Sprintf("X-Frame-Options %q uses obsolete ALLOW-FROM, which modern browsers ignore entirely", v)}
				default:
					return []string{fmt.Sprintf("X-Frame-Options value %q is invalid (want DENY or SAMEORIGIN)", v)}
				}
			},
		},
		{
			ID: "csp-missing", Category: "security", Severity: Info,
			Summary: "HTML response without an enforcing Content-Security-Policy",
			Advice: "A CSP is the strongest defense-in-depth against XSS. Start with " +
				"`Content-Security-Policy-Report-Only`, then enforce. Report-Only alone never blocks.",
			Cite: citeCSP3,
			Check: func(t *Target) []string {
				if !isHTML(t) || t.Resp.Has("Content-Security-Policy") {
					return nil
				}
				if t.Resp.Has("Content-Security-Policy-Report-Only") {
					return []string{"only Content-Security-Policy-Report-Only is set; report-only policies observe but never block"}
				}
				return []string{"HTML response has no Content-Security-Policy"}
			},
		},
		{
			ID: "csp-unsafe-inline", Category: "security", Severity: Warn,
			Summary: "CSP script policy allows 'unsafe-inline' without nonce or hash",
			Advice: "With 'unsafe-inline' and no nonce/hash/'strict-dynamic', any injected " +
				"<script> executes and the CSP provides no XSS protection. Move to nonces or hashes.",
			Cite: citeCSP3,
			Check: func(t *Target) []string {
				sources, ok := cspScriptSources(t)
				if !ok || !sourceListContains(sources, "'unsafe-inline'") {
					return nil
				}
				for _, s := range sources {
					l := strings.ToLower(s)
					if strings.HasPrefix(l, "'nonce-") || strings.HasPrefix(l, "'sha256-") ||
						strings.HasPrefix(l, "'sha384-") || strings.HasPrefix(l, "'sha512-") ||
						l == "'strict-dynamic'" {
						// Nonce/hash presence makes browsers ignore
						// 'unsafe-inline', so the policy is still strict.
						return nil
					}
				}
				return []string{"CSP script policy allows 'unsafe-inline' with no nonce or hash, neutralizing XSS protection"}
			},
		},
		{
			ID: "csp-wildcard-script", Category: "security", Severity: Warn,
			Summary: "CSP script policy allows scripts from any origin (*)",
			Advice: "A bare `*` in script-src (or in default-src when script-src is absent) lets " +
				"attacker-hosted scripts run. Enumerate the origins you actually load from.",
			Cite: citeCSP3,
			Check: func(t *Target) []string {
				sources, ok := cspScriptSources(t)
				if ok && sourceListContains(sources, "*") {
					return []string{"CSP script policy contains a bare * source, allowing scripts from any origin"}
				}
				return nil
			},
		},
		{
			ID: "cookie-no-secure", Category: "security", Severity: Error, HTTPSOnly: true,
			Summary: "Set-Cookie on HTTPS without the Secure attribute",
			Advice: "Without Secure, the cookie is also sent over plaintext HTTP, where an active " +
				"network attacker can read or fixate it. Add `; Secure` to every cookie on an HTTPS site.",
			Cite: RFC(6265, "4.1.2.5"),
			Check: cookieCheck(func(c httpsyntax.Cookie) string {
				if !c.HasAttr("Secure") {
					return fmt.Sprintf("cookie %q is set without the Secure attribute on an HTTPS response", c.Name)
				}
				return ""
			}),
		},
		{
			ID: "cookie-no-httponly", Category: "security", Severity: Warn,
			Summary: "Set-Cookie without the HttpOnly attribute",
			Advice: "HttpOnly keeps the cookie out of document.cookie, so a script injection " +
				"cannot exfiltrate the session. Omit it only for cookies JavaScript genuinely reads.",
			Cite: RFC(6265, "4.1.2.6"),
			Check: cookieCheck(func(c httpsyntax.Cookie) string {
				if !c.HasAttr("HttpOnly") {
					return fmt.Sprintf("cookie %q is readable from JavaScript (no HttpOnly attribute)", c.Name)
				}
				return ""
			}),
		},
		{
			ID: "cookie-no-samesite", Category: "security", Severity: Warn,
			Summary: "Set-Cookie without a SameSite attribute",
			Advice: "Browsers default an absent SameSite to Lax, but the default varies and CSRF " +
				"defenses should not rest on it. State the intent: Lax, Strict, or None (with Secure).",
			Cite: cite6265bis,
			Check: cookieCheck(func(c httpsyntax.Cookie) string {
				if !c.HasAttr("SameSite") {
					return fmt.Sprintf("cookie %q has no SameSite attribute (cross-site behavior is left to browser defaults)", c.Name)
				}
				return ""
			}),
		},
		{
			ID: "cookie-samesite-none-insecure", Category: "security", Severity: Error,
			Summary: "SameSite=None cookie without Secure",
			Advice: "SameSite=None is only valid together with Secure; browsers reject the cookie " +
				"otherwise. If the cookie must flow cross-site, it must also be HTTPS-only.",
			Cite: cite6265bis,
			Check: cookieCheck(func(c httpsyntax.Cookie) string {
				ss, ok := c.Attr("SameSite")
				if ok && strings.EqualFold(ss, "None") && !c.HasAttr("Secure") {
					return fmt.Sprintf("cookie %q sets SameSite=None without Secure; browsers reject this combination", c.Name)
				}
				return ""
			}),
		},
		{
			ID: "cors-wildcard-credentials", Category: "security", Severity: Error,
			Summary: "Access-Control-Allow-Origin * combined with credentials",
			Advice: "The CORS protocol forbids the wildcard origin when " +
				"Access-Control-Allow-Credentials is true; browsers block the response. Servers that " +
				"reflect arbitrary origins with credentials instead re-open the same hole deliberately.",
			Cite: citeFetchCORS,
			Check: func(t *Target) []string {
				origin, _ := t.Resp.Get("Access-Control-Allow-Origin")
				creds, _ := t.Resp.Get("Access-Control-Allow-Credentials")
				if strings.Trim(origin, " \t") == "*" && strings.EqualFold(strings.Trim(creds, " \t"), "true") {
					return []string{"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is forbidden by the CORS protocol"}
				}
				return nil
			},
		},
		{
			ID: "server-version", Category: "security", Severity: Info,
			Summary: "Server header discloses a version number",
			Advice: "RFC 9110 warns that detailed Server values help attackers target known-vulnerable " +
				"versions. Strip the version: `Server: nginx` says enough.",
			Cite: RFC(9110, "10.2.4"),
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("Server")
				if ok && productHasVersion(v) {
					return []string{fmt.Sprintf("Server value %q reveals a product version", v)}
				}
				return nil
			},
		},
		{
			ID: "x-powered-by", Category: "security", Severity: Info,
			Summary: "X-Powered-By discloses the technology stack",
			Advice: "X-Powered-By serves no protocol purpose and advertises your framework and " +
				"often its version. Remove the header at the server or framework level.",
			Cite: citeOWASPHeaders,
			Check: func(t *Target) []string {
				if v, ok := t.Resp.Get("X-Powered-By"); ok {
					return []string{fmt.Sprintf("X-Powered-By: %s discloses implementation details for no benefit", v)}
				}
				return nil
			},
		},
		{
			ID: "xss-protection-legacy", Category: "security", Severity: Info,
			Summary: "X-XSS-Protection enables the retired XSS auditor",
			Advice: "Every major browser has removed the XSS auditor, and enabling it in old " +
				"browsers created cross-site information leaks. Send `X-XSS-Protection: 0` or drop the header.",
			Cite: citeOWASPHeaders,
			Check: func(t *Target) []string {
				v, ok := t.Resp.Get("X-XSS-Protection")
				if ok && strings.Trim(v, " \t") != "0" {
					return []string{fmt.Sprintf("X-XSS-Protection: %s re-enables a retired, leak-prone auditor; send 0 or remove the header", v)}
				}
				return nil
			},
		},
		{
			ID: "referrer-policy-missing", Category: "security", Severity: Info,
			Summary: "HTML response without a Referrer-Policy",
			Advice: "Without a policy, some browsers still send the full URL — including path and " +
				"query — to other origins. `strict-origin-when-cross-origin` is the safe modern default.",
			Cite: citeReferrerPolicy,
			Check: func(t *Target) []string {
				if isHTML(t) && !t.Resp.Has("Referrer-Policy") {
					return []string{"HTML response has no Referrer-Policy; full URLs may leak in the Referer header"}
				}
				return nil
			},
		},
	}
}

// --- shared helpers -------------------------------------------------------

// bodylessStatus reports statuses defined to never carry content.
func bodylessStatus(code int) bool {
	return (code >= 100 && code < 200) || code == 204 || code == 304
}

// isHTML reports whether the response declares an HTML document type.
func isHTML(t *Target) bool {
	v, ok := t.Resp.Get("Content-Type")
	if !ok {
		return false
	}
	mt, err := httpsyntax.ParseMediaType(v)
	return err == nil && mt.IsHTML()
}

// cookieCheck lifts a per-cookie predicate over every Set-Cookie field.
func cookieCheck(f func(httpsyntax.Cookie) string) func(*Target) []string {
	return func(t *Target) []string {
		var out []string
		for _, v := range t.Resp.Values("Set-Cookie") {
			c, err := httpsyntax.ParseSetCookie(v)
			if err != nil {
				continue // shape errors belong to other tooling
			}
			if msg := f(c); msg != "" {
				out = append(out, msg)
			}
		}
		return out
	}
}

// checkHSTSSyntax validates a Strict-Transport-Security value against the
// RFC 6797 §6.1 grammar and returns the problems found.
func checkHSTSSyntax(v string) []string {
	var out []string
	seenMaxAge := false
	for _, part := range strings.Split(v, ";") {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		name, arg, has := strings.Cut(part, "=")
		name = strings.Trim(name, " \t")
		if !httpsyntax.IsToken(name) {
			out = append(out, fmt.Sprintf("HSTS directive name %q is not a valid token", name))
			continue
		}
		if strings.EqualFold(name, "max-age") {
			seenMaxAge = true
			arg = strings.Trim(arg, " \t")
			if unq, ok := httpsyntax.Unquote(arg); ok {
				arg = unq
			}
			if _, ok := httpsyntax.ParseDeltaSeconds(arg); !has || !ok {
				out = append(out, fmt.Sprintf("HSTS max-age value %q is not a non-negative integer", arg))
			}
		}
	}
	if !seenMaxAge {
		out = append(out, "HSTS policy lacks the required max-age directive and will be ignored")
	}
	return out
}

// hstsMaxAge extracts a syntactically valid max-age, if any.
func hstsMaxAge(v string) (int64, bool) {
	for _, part := range strings.Split(v, ";") {
		part = strings.Trim(part, " \t")
		name, arg, has := strings.Cut(part, "=")
		if !has || !strings.EqualFold(strings.Trim(name, " \t"), "max-age") {
			continue
		}
		arg = strings.Trim(arg, " \t")
		if unq, ok := httpsyntax.Unquote(arg); ok {
			arg = unq
		}
		return httpsyntax.ParseDeltaSeconds(arg)
	}
	return 0, false
}

// cspDirectives splits a CSP policy into directives: name → source list.
// The first occurrence of a directive wins, as the CSP algorithm ignores
// duplicates.
func cspDirectives(policy string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, dup := out[name]; !dup {
			out[name] = fields[1:]
		}
	}
	return out
}

// cspHasDirective reports whether the policy defines the directive.
func cspHasDirective(policy, name string) bool {
	_, ok := cspDirectives(policy)[name]
	return ok
}

// cspScriptSources resolves the source list governing scripts: script-src
// when present, else default-src. ok is false when neither exists.
func cspScriptSources(t *Target) ([]string, bool) {
	policy, present := t.Resp.Get("Content-Security-Policy")
	if !present {
		return nil, false
	}
	dirs := cspDirectives(policy)
	if s, ok := dirs["script-src"]; ok {
		return s, true
	}
	if s, ok := dirs["default-src"]; ok {
		return s, true
	}
	return nil, false
}

// sourceListContains does a case-insensitive membership test.
func sourceListContains(sources []string, want string) bool {
	for _, s := range sources {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// productHasVersion reports whether a Server-style product string carries
// a version: a '/' immediately followed by a digit ("nginx/1.25.3").
func productHasVersion(v string) bool {
	for i := 0; i < len(v)-1; i++ {
		if v[i] == '/' && v[i+1] >= '0' && v[i+1] <= '9' {
			return true
		}
	}
	return false
}
