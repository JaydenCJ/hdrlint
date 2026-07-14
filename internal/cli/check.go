package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/httpmsg"
	"github.com/JaydenCJ/hdrlint/internal/render"
	"github.com/JaydenCJ/hdrlint/internal/rules"
)

// runCheck implements `hdrlint check`. stdin is injectable for tests;
// nil means os.Stdin.
func runCheck(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := newFlagSet("check", stderr)
	format := fs.String("format", "text", "output format: text, json, or github")
	failOn := fs.String("fail-on", "error", "lowest severity that fails the run: error, warn, info, or never")
	httpCapture := fs.Bool("http", false, "capture was served over plain HTTP (skips HTTPS-only rules)")
	var disable, only multiFlag
	fs.Var(&disable, "disable", "rule id to skip (repeatable)")
	fs.Var(&only, "only", "run only this rule id (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	switch *format {
	case "text", "json", "github":
	default:
		fmt.Fprintf(stderr, "hdrlint: unknown format %q (want text, json, or github)\n", *format)
		return ExitUsage
	}
	var failLevel rules.Severity
	failNever := *failOn == "never"
	if !failNever {
		var err error
		failLevel, err = rules.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintf(stderr, "hdrlint: --fail-on: unknown value %q (want error, warn, info, or never)\n", *failOn)
			return ExitUsage
		}
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "hdrlint: no input; pass one or more capture files, or \"-\" for stdin")
		return ExitUsage
	}

	engine, err := rules.NewEngine(disable, only)
	if err != nil {
		fmt.Fprintf(stderr, "hdrlint: %v\n", err)
		return ExitUsage
	}
	if stdin == nil {
		stdin = os.Stdin
	}

	var results []render.ResponseResult
	for _, path := range paths {
		responses, err := loadCapture(path, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "hdrlint: %s: %v\n", path, err)
			return ExitRuntime
		}
		for _, resp := range responses {
			t := &rules.Target{Resp: resp, HTTPS: targetHTTPS(resp, *httpCapture)}
			results = append(results, render.ResponseResult{
				Resp:     resp,
				Findings: engine.Run(t),
			})
		}
	}

	switch *format {
	case "text":
		render.Text(stdout, results, engine.Len())
	case "json":
		if err := render.JSON(stdout, results); err != nil {
			fmt.Fprintf(stderr, "hdrlint: %v\n", err)
			return ExitRuntime
		}
	case "github":
		render.GitHub(stdout, results)
	}

	if failNever {
		return ExitOK
	}
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule.Severity >= failLevel {
				return ExitFindings
			}
		}
	}
	return ExitOK
}

// targetHTTPS decides the transport context for one response: HAR
// captures know their URL; raw captures are assumed HTTPS unless --http.
func targetHTTPS(resp *httpmsg.Response, httpFlag bool) bool {
	if resp.URL != "" {
		return resp.IsHTTPS()
	}
	return !httpFlag
}

// loadCapture reads one input (a file path or "-" for stdin) and parses
// it as HAR or a raw dump, sniffing by extension and first byte.
func loadCapture(path string, stdin io.Reader) ([]*httpmsg.Response, error) {
	var data []byte
	var err error
	source := path
	if path == "-" {
		data, err = io.ReadAll(stdin)
		source = "stdin"
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if isHARInput(path, data) {
		return httpmsg.ParseHAR(data, source)
	}
	return httpmsg.ParseRaw(data, source)
}

// isHARInput sniffs the capture kind: a .har extension, or JSON content
// (raw HTTP captures can never start with '{').
func isHARInput(path string, data []byte) bool {
	if strings.HasSuffix(strings.ToLower(path), ".har") {
		return true
	}
	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	return strings.HasPrefix(trimmed, "{")
}
