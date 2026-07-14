package httpmsg

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// harFile mirrors the subset of the HAR 1.2 format hdrlint reads. Unknown
// keys are ignored, so archives from any browser or proxy work.
type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
			Response struct {
				Status      int    `json:"status"`
				StatusText  string `json:"statusText"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// ParseHAR parses a HAR archive and returns one Response per completed
// entry. Entries with status 0 (aborted or blocked requests) carry no
// server headers and are skipped.
func ParseHAR(data []byte, source string) ([]*Response, error) {
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("not a valid HAR file: %w", err)
	}
	if len(har.Log.Entries) == 0 {
		return nil, errors.New("HAR file contains no entries")
	}
	var responses []*Response
	for _, e := range har.Log.Entries {
		if e.Response.Status == 0 {
			continue
		}
		resp := &Response{
			Source:     source,
			Index:      len(responses) + 1,
			Proto:      normalizeHARProto(e.Response.HTTPVersion),
			StatusCode: e.Response.Status,
			Reason:     e.Response.StatusText,
			URL:        e.Request.URL,
		}
		for _, h := range e.Response.Headers {
			resp.Fields = append(resp.Fields, Field{
				Name:  h.Name,
				Value: strings.Trim(h.Value, " \t"),
			})
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		return nil, errors.New("HAR file contains no completed responses")
	}
	return responses, nil
}

// IsHTTPS reports whether the response is known to have been served over
// TLS. Only HAR captures carry the request URL; raw captures rely on the
// caller's --http flag instead.
func (r *Response) IsHTTPS() bool {
	return strings.HasPrefix(strings.ToLower(r.URL), "https:")
}

// normalizeHARProto maps HAR httpVersion spellings ("http/2.0", "h2",
// "HTTP/1.1") onto the status-line form used everywhere else.
func normalizeHARProto(v string) string {
	switch strings.ToLower(v) {
	case "h2", "http/2", "http/2.0":
		return "HTTP/2"
	case "h3", "http/3", "http/3.0":
		return "HTTP/3"
	case "":
		return "HTTP/1.1"
	default:
		return strings.ToUpper(v)
	}
}
