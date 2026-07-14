// Package cli implements the hdrlint command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/hdrlint/internal/render"
	"github.com/JaydenCJ/hdrlint/internal/rules"
	"github.com/JaydenCJ/hdrlint/internal/version"
)

// Exit codes. Documented in the README; `check` uses ExitFindings as its
// machine-readable verdict.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitRuntime  = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr, nil)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "hdrlint %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		if strings.HasPrefix(args[0], "-") && args[0] != "-" {
			fmt.Fprintf(stderr, "hdrlint: unknown flag %q before a subcommand\n\n", args[0])
			usage(stderr)
			return ExitUsage
		}
		// Bare path (or "-" for stdin): treat as `check <path>`.
		return runCheck(args, stdout, stderr, nil)
	}
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// newFlagSet builds a silent FlagSet whose errors we render ourselves.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// runRules implements `hdrlint rules`.
func runRules(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("rules", stderr)
	format := fs.String("format", "text", "output format: text or json")
	category := fs.String("category", "", "only rules in this category (security, caching, correctness)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	catalog := rules.All()
	if *category != "" {
		var filtered []*rules.Rule
		for _, r := range catalog {
			if r.Category == *category {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(stderr, "hdrlint: unknown category %q (want security, caching, or correctness)\n", *category)
			return ExitUsage
		}
		catalog = filtered
	}
	switch *format {
	case "text":
		render.RulesText(stdout, catalog)
	case "json":
		if err := render.RulesJSON(stdout, catalog); err != nil {
			fmt.Fprintf(stderr, "hdrlint: %v\n", err)
			return ExitRuntime
		}
	default:
		fmt.Fprintf(stderr, "hdrlint: unknown format %q (want text or json)\n", *format)
		return ExitUsage
	}
	return ExitOK
}

// runExplain implements `hdrlint explain <rule-id>`.
func runExplain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: hdrlint explain <rule-id>")
		return ExitUsage
	}
	r, ok := rules.ByID(args[0])
	if !ok {
		fmt.Fprintf(stderr, "hdrlint: unknown rule id %q (run `hdrlint rules` for the catalog)\n", args[0])
		return ExitUsage
	}
	render.ExplainText(stdout, r)
	return ExitOK
}

// usage prints the top-level help text.
func usage(w io.Writer) {
	fmt.Fprintf(w, `hdrlint %s — lint HTTP response headers, with an RFC citation per finding

usage:
  hdrlint check [flags] <capture>...   lint one or more captures ("-" = stdin)
  hdrlint rules [flags]                list every rule with severity and citation
  hdrlint explain <rule-id>            show a rule's advice and cited spec text
  hdrlint version                      print the version

captures are read offline: raw header dumps (curl -i, curl -sD -, curl -siL
redirect chains, devtools copy-paste) or HAR archives (*.har or JSON input).

check flags:
  --format text|json|github         report format (default text)
  --fail-on error|warn|info|never   lowest severity that fails the run (default error)
  --disable <rule-id>               skip a rule (repeatable)
  --only <rule-id>                  run only these rules (repeatable)
  --http                            capture was served over plain HTTP, not HTTPS

rules flags:
  --format text|json          catalog format (default text)
  --category <category>       only security, caching, or correctness rules

exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage error,
3 unreadable or unparseable input.
`, version.Version)
}
