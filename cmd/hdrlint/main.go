// Command hdrlint lints HTTP response headers for security, caching, and
// spec violations, citing the governing RFC for every finding.
package main

import (
	"os"

	"github.com/JaydenCJ/hdrlint/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
