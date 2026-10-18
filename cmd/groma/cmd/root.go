package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	verbose bool
	output  string
)

var rootCmd = &cobra.Command{
	Use:   "groma",
	Short: "Network vulnerability scanner",
	Long: `groma discovers open ports and services on a host, fingerprints
service versions, and matches them against a declarative YAML check
library to find known vulnerabilities.

Port discovery uses naabu when it's installed on $PATH (fast, with
native service-version fingerprinting) and falls back to groma's own
zero-dependency TCP-connect scanner otherwise. Either way the default
is every TCP port, 1-65535 — groma never silently narrows to a top-N
subset unless you ask it to with --fast.

Examples:
  # Scan a single host, every TCP port (the default)
  groma scan 10.0.0.5

  # Faster, narrower first pass (naabu's/groma's own top-N ports)
  groma scan --fast 10.0.0.5

  # Load a check library and emit JSON
  groma scan --checks ./checks -o report.json --format json 10.0.0.5

  # CI gate: fail the build (exit code 2) on a high-or-above finding
  groma scan --checks ./checks --fail-on high 10.0.0.5`,
	Version: version,
}

// Execute adds all child commands to the root command and runs it.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	rootCmd.SetVersionTemplate(fmt.Sprintf("{{.Name}} version {{.Version}} (commit: %s, built: %s)\n", commit, date))
}
