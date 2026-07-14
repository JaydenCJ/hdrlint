package httpsyntax

import (
	"errors"
	"strings"
)

// Cookie is a parsed Set-Cookie line: the cookie-pair plus its attributes
// in order, per RFC 6265 §4.1.1.
type Cookie struct {
	Name  string
	Value string
	Attrs []CookieAttr
}

// CookieAttr is one cookie attribute (Secure, Max-Age=3600, …).
type CookieAttr struct {
	Name  string // as written
	Value string
}

// Attr returns the first attribute matching name case-insensitively
// (attribute names are case-insensitive per RFC 6265 §5.2).
func (c Cookie) Attr(name string) (string, bool) {
	for _, a := range c.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

// HasAttr reports whether the attribute is present at all.
func (c Cookie) HasAttr(name string) bool {
	_, ok := c.Attr(name)
	return ok
}

// ParseSetCookie parses a Set-Cookie field value. It is deliberately
// lenient about cookie values (real servers emit all sorts) but requires
// the leading name=value pair that RFC 6265 §4.1.1 mandates.
func ParseSetCookie(v string) (Cookie, error) {
	var c Cookie
	parts := strings.Split(v, ";")
	name, val, ok := strings.Cut(parts[0], "=")
	name = strings.Trim(name, " \t")
	if !ok || name == "" {
		return c, errors.New("missing name=value cookie-pair")
	}
	c.Name = name
	c.Value = strings.Trim(val, " \t")
	for _, raw := range parts[1:] {
		raw = strings.Trim(raw, " \t")
		if raw == "" {
			continue
		}
		an, av, _ := strings.Cut(raw, "=")
		c.Attrs = append(c.Attrs, CookieAttr{
			Name:  strings.Trim(an, " \t"),
			Value: strings.Trim(av, " \t"),
		})
	}
	return c, nil
}
