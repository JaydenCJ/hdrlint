package httpmsg

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// statusLineRe matches an HTTP/1.x or HTTP/2 style status line at the start
// of a line: protocol, 3-digit status, optional reason phrase. curl prints
// "HTTP/2 200" (no minor version, no reason) for HTTP/2 responses.
var statusLineRe = regexp.MustCompile(`^(HTTP/[0-9](?:\.[0-9])?) ([0-9]{3})(?: +(.*))?$`)

// headerishRe loosely matches a "Name: value" line so a pasted header list
// without a status line is still recognized as a capture. The name part is
// deliberately permissive — invalid names must reach the rule engine.
var headerishRe = regexp.MustCompile(`^[^:\s]+:`)

// ParseRaw parses a raw capture: one or more responses as produced by
// `curl -i`, `curl -sD -`, `curl -siL` (redirect chains), or a devtools
// copy-paste of response headers without a status line.
//
// Grammar, per block:
//
//	status line → header lines → blank line → optional body
//
// Body content is skipped until the next line that begins a new status
// line. A capture whose first significant line is "Name: value" instead of
// a status line is treated as a single headers-only response.
func ParseRaw(data []byte, source string) ([]*Response, error) {
	lines := splitLines(string(data))
	var responses []*Response

	const (
		stSeeking = iota // before the first block
		stHeaders        // inside a header block
		stBody           // after a block, skipping body bytes
	)
	state := stSeeking
	var cur *Response

	startResponse := func(proto string, code int, reason string) {
		cur = &Response{
			Source:     source,
			Index:      len(responses) + 1,
			Proto:      proto,
			StatusCode: code,
			Reason:     reason,
		}
		responses = append(responses, cur)
		state = stHeaders
	}

	for _, line := range lines {
		if m := statusLineRe.FindStringSubmatch(line); m != nil && state != stHeaders {
			code, _ := strconv.Atoi(m[2])
			startResponse(m[1], code, strings.TrimRight(m[3], " \t"))
			continue
		}
		switch state {
		case stSeeking:
			if strings.TrimSpace(line) == "" {
				continue
			}
			if headerishRe.MatchString(line) {
				// Headers-only capture: everything is one response.
				startResponse("", 0, "")
				addFieldLine(cur, line)
				continue
			}
			return nil, errors.New("input does not start with an HTTP status line or a header field line")
		case stHeaders:
			if strings.TrimSpace(line) == "" {
				// Blank line ends the header block. Headers-only
				// captures keep going: pastes often contain stray
				// blank lines and never carry a body.
				if cur.StatusCode != 0 {
					state = stBody
				}
				continue
			}
			addFieldLine(cur, line)
		case stBody:
			// Skipped: body bytes between responses in a `curl -i` capture.
		}
	}

	if len(responses) == 0 {
		return nil, errors.New("no HTTP responses found in input")
	}
	return responses, nil
}

// addFieldLine appends one header line to resp, handling continuation
// lines (obs-fold) and colon-less garbage.
func addFieldLine(resp *Response, line string) {
	if line[0] == ' ' || line[0] == '\t' {
		// Obsolete line folding: continuation of the previous field.
		if n := len(resp.Fields); n > 0 && !resp.Fields[n-1].NoColon {
			f := &resp.Fields[n-1]
			f.Value = strings.TrimRight(f.Value+" "+strings.Trim(line, " \t"), " \t")
			f.ObsFolded = true
			return
		}
		// A continuation with nothing to continue: keep it as garbage.
		resp.Fields = append(resp.Fields, Field{Name: strings.Trim(line, " \t"), NoColon: true})
		return
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		resp.Fields = append(resp.Fields, Field{Name: line, NoColon: true})
		return
	}
	resp.Fields = append(resp.Fields, Field{
		Name:  name,
		Value: strings.Trim(value, " \t"),
	})
}

// splitLines splits on LF, tolerating CRLF and a missing final newline.
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}
