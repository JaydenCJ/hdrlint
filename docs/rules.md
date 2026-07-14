# hdrlint rule reference

All 50 rules, generated from the same catalog the binary runs
(`hdrlint rules --format json` emits it machine-readably). Every rule
carries a citation to the text that makes the finding true: an IETF RFC
wherever one governs the header, otherwise the WHATWG/W3C living standard,
and — for two pure-hygiene headers no spec owns — the OWASP Secure Headers
Project. `hdrlint explain <rule-id>` prints the remediation advice and the
citation URL for any row below.

Severity semantics:

| Severity | Meaning | Default effect |
|---|---|---|
| error | MUST-level spec violation or exploitable misconfiguration | fails the run |
| warn | SHOULD-level violation or risky default | reported; fails with `--fail-on warn` |
| info | hardening advice and dead-weight headers | reported; fails with `--fail-on info` |

Rules marked HTTPS-only (`hsts-missing`, `cookie-no-secure`) are skipped
when a capture is declared plain-HTTP with `--http`, or when a HAR entry's
request URL is `http://`; `hsts-over-http` runs only then.

## security (20 rules)

| Rule | Severity | What it checks | Citation |
|---|---|---|---|
| `cookie-no-httponly` | warn | Set-Cookie without the HttpOnly attribute | [RFC 6265 §4.1.2.6](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.6) |
| `cookie-no-samesite` | warn | Set-Cookie without a SameSite attribute | [RFC 6265bis §4.1.2.7](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.2.7) |
| `cookie-no-secure` | error | Set-Cookie on HTTPS without the Secure attribute | [RFC 6265 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.5) |
| `cookie-samesite-none-insecure` | error | SameSite=None cookie without Secure | [RFC 6265bis §4.1.2.7](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.2.7) |
| `cors-wildcard-credentials` | error | Access-Control-Allow-Origin * combined with credentials | [WHATWG Fetch](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials) |
| `csp-missing` | info | HTML response without an enforcing Content-Security-Policy | [W3C CSP3](https://www.w3.org/TR/CSP3/) |
| `csp-unsafe-inline` | warn | CSP script policy allows 'unsafe-inline' without nonce or hash | [W3C CSP3](https://www.w3.org/TR/CSP3/) |
| `csp-wildcard-script` | warn | CSP script policy allows scripts from any origin (*) | [W3C CSP3](https://www.w3.org/TR/CSP3/) |
| `frame-protection-missing` | info | HTML response with neither frame-ancestors nor X-Frame-Options | [RFC 7034 §2.1](https://www.rfc-editor.org/rfc/rfc7034#section-2.1) |
| `hsts-malformed` | error | Strict-Transport-Security value violates the RFC 6797 grammar | [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797#section-6.1) |
| `hsts-missing` | warn | HTTPS response without Strict-Transport-Security | [RFC 6797 §7.1](https://www.rfc-editor.org/rfc/rfc6797#section-7.1) |
| `hsts-over-http` | warn | Strict-Transport-Security sent over plain HTTP | [RFC 6797 §7.2](https://www.rfc-editor.org/rfc/rfc6797#section-7.2) |
| `hsts-short-max-age` | warn | HSTS max-age below 180 days | [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797#section-6.1.1) |
| `nosniff-invalid` | warn | X-Content-Type-Options has a value other than nosniff | [WHATWG Fetch](https://fetch.spec.whatwg.org/#x-content-type-options-header) |
| `nosniff-missing` | warn | X-Content-Type-Options: nosniff is absent | [WHATWG Fetch](https://fetch.spec.whatwg.org/#x-content-type-options-header) |
| `referrer-policy-missing` | info | HTML response without a Referrer-Policy | [W3C Referrer Policy](https://www.w3.org/TR/referrer-policy/) |
| `server-version` | info | Server header discloses a version number | [RFC 9110 §10.2.4](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.4) |
| `x-powered-by` | info | X-Powered-By discloses the technology stack | [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/) |
| `xfo-invalid` | warn | X-Frame-Options value is not DENY or SAMEORIGIN | [RFC 7034 §2.1](https://www.rfc-editor.org/rfc/rfc7034#section-2.1) |
| `xss-protection-legacy` | info | X-XSS-Protection enables the retired XSS auditor | [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/) |

## caching (14 rules)

| Rule | Severity | What it checks | Citation |
|---|---|---|---|
| `age-invalid` | warn | Age is not a non-negative integer | [RFC 9111 §5.1](https://www.rfc-editor.org/rfc/rfc9111#section-5.1) |
| `cache-control-malformed` | warn | Cache-Control value violates the list grammar | [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111#section-5.2) |
| `cache-control-missing` | info | 200 response without a Cache-Control header | [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111#section-5.2) |
| `cache-invalid-max-age` | error | max-age or s-maxage argument is not a non-negative integer | [RFC 9111 §5.2.2.1](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.1) |
| `cache-no-store-conflict` | error | no-store combined with directives that grant caching | [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.5) |
| `cache-private-smaxage` | warn | private combined with s-maxage | [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.10) |
| `cache-public-private` | error | Cache-Control sets both public and private | [RFC 9111 §5.2.2](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2) |
| `cache-unknown-directive` | info | Unrecognized or request-only Cache-Control directive | [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111#section-5.2) |
| `etag-malformed` | error | ETag is not a valid entity-tag | [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3) |
| `expires-ignored` | info | Expires is overridden by Cache-Control max-age | [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111#section-5.3) |
| `expires-invalid` | warn | Expires is not a valid HTTP-date | [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111#section-5.3) |
| `last-modified-future` | warn | Last-Modified is later than the Date header | [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110#section-8.8.2) |
| `pragma-response` | info | Pragma has no meaning in responses and is deprecated | [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111#section-5.4) |
| `vary-wildcard` | warn | Vary: * makes the response effectively uncacheable | [RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5) |

## correctness (16 rules)

| Rule | Severity | What it checks | Citation |
|---|---|---|---|
| `allow-missing-405` | error | 405 response without an Allow header | [RFC 9110 §15.5.6](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6) |
| `charset-missing` | info | text/html without an explicit charset | [WHATWG HTML](https://html.spec.whatwg.org/multipage/semantics.html#charset) |
| `content-length-invalid` | error | Content-Length is not a valid length | [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6) |
| `content-length-status` | error | Content-Length on a 1xx or 204 response | [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6) |
| `content-length-transfer-encoding` | error | Content-Length and Transfer-Encoding sent together | [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112#section-6.3) |
| `content-type-malformed` | error | Content-Type is not a valid media type | [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1) |
| `content-type-missing` | warn | Response with content but no Content-Type | [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110#section-8.3) |
| `date-invalid` | error | Date or Last-Modified is not a valid HTTP-date | [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110#section-5.6.7) |
| `date-missing` | warn | Response without a Date header | [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110#section-6.6.1) |
| `date-obsolete-format` | warn | Timestamp uses an obsolete HTTP-date form | [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110#section-5.6.7) |
| `duplicate-singleton` | error | A singleton header appears more than once | [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110#section-5.3) |
| `field-name-invalid` | error | Header field name is not a valid token | [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110#section-5.1) |
| `field-value-invalid` | error | Header field value contains a forbidden byte | [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110#section-5.5) |
| `obs-fold` | error | Header value uses obsolete line folding | [RFC 9112 §5.2](https://www.rfc-editor.org/rfc/rfc9112#section-5.2) |
| `redirect-location-missing` | warn | Redirect status without a Location header | [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110#section-15.4) |
| `retry-after-invalid` | warn | Retry-After is neither delta-seconds nor an HTTP-date | [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3) |
