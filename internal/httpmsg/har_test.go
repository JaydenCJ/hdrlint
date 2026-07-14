// Tests for HAR archive parsing.
package httpmsg

import "testing"

const sampleHAR = `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "request": {"method": "GET", "url": "https://example.test/api"},
        "response": {
          "status": 200, "statusText": "OK", "httpVersion": "http/2.0",
          "headers": [
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Cache-Control", "value": "no-store"}
          ]
        }
      },
      {
        "request": {"method": "GET", "url": "http://example.test/legacy"},
        "response": {
          "status": 301, "statusText": "Moved Permanently", "httpVersion": "HTTP/1.1",
          "headers": [{"name": "Location", "value": "https://example.test/"}]
        }
      },
      {
        "request": {"method": "GET", "url": "https://example.test/aborted"},
        "response": {"status": 0, "statusText": "", "httpVersion": "", "headers": []}
      }
    ]
  }
}`

func TestParseHARBasic(t *testing.T) {
	resps, err := ParseHAR([]byte(sampleHAR), "cap.har")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The aborted (status 0) entry is skipped: it has no server headers.
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2", len(resps))
	}
	r := resps[0]
	if r.StatusCode != 200 || r.URL != "https://example.test/api" {
		t.Fatalf("first entry parsed as %+v", r)
	}
	if v, ok := r.Get("cache-control"); !ok || v != "no-store" {
		t.Fatalf("Cache-Control = (%q, %v)", v, ok)
	}
	if r.Proto != "HTTP/2" {
		t.Fatalf("httpVersion normalized to %q, want HTTP/2", r.Proto)
	}
}

func TestParseHARSchemeDetection(t *testing.T) {
	resps, err := ParseHAR([]byte(sampleHAR), "cap.har")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resps[0].IsHTTPS() {
		t.Error("https:// URL not detected as HTTPS")
	}
	if resps[1].IsHTTPS() {
		t.Error("http:// URL wrongly detected as HTTPS")
	}
}

func TestParseHARRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"not JSON":     "HTTP/1.1 200 OK",
		"empty log":    `{"log": {"entries": []}}`,
		"only aborted": `{"log": {"entries": [{"request": {"url": "https://example.test/"}, "response": {"status": 0, "headers": []}}]}}`,
	}
	for name, in := range cases {
		if _, err := ParseHAR([]byte(in), "cap.har"); err == nil {
			t.Errorf("%s: ParseHAR succeeded, want error", name)
		}
	}
}

func TestIsHTTPSOnRawCapture(t *testing.T) {
	// Raw captures have no URL; IsHTTPS must be false so the CLI's
	// --http flag (not the response) decides the transport context.
	r := &Response{Source: "cap.txt"}
	if r.IsHTTPS() {
		t.Fatal("URL-less response claimed to be HTTPS")
	}
}
