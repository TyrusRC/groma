package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/TyrusRC/groma/internal/checks"
	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/detection/legacyprotocol"
	"github.com/TyrusRC/groma/internal/discovery"
	"github.com/TyrusRC/groma/internal/haruspex"
	"github.com/TyrusRC/groma/internal/reporting"
	"github.com/TyrusRC/groma/internal/tools/naabu"
)

var (
	scanPorts       string
	scanFast        bool
	scanChecksDir   string
	scanFormat      string
	scanFailOn      string
	scanTimeout     time.Duration
	scanConcurrency int
	scanRate        int
	scanHaruspexURL string
	scanNoTriage    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <host> [host...]",
	Short: "Scan one or more hosts for open ports, services, and known vulnerabilities",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanPorts, "ports", "", "explicit port list/range (nmap format, e.g. \"80,443\" or \"1-1000\"); overrides --fast")
	scanCmd.Flags().BoolVar(&scanFast, "fast", false, "scan only a top-N ports subset instead of the full 1-65535 default (quicker, NOT exhaustive)")
	scanCmd.Flags().StringVar(&scanChecksDir, "checks", "", "directory of check YAML files to load and match (default: none — port/service discovery only)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "output format: text, json, sarif")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "exit code 2 if a finding at or above this severity is found (none|low|medium|high|critical)")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout per host")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 0, "worker concurrency passed to naabu (0 = auto, ulimit-aware)")
	scanCmd.Flags().IntVar(&scanRate, "rate", 0, "packets/sec rate limit passed to naabu (0 = naabu's own default)")
	scanCmd.Flags().StringVar(&scanHaruspexURL, "haruspex-url", "", "Haruspex decision server base URL for finding triage (default: http://127.0.0.1:3000)")
	scanCmd.Flags().BoolVar(&scanNoTriage, "no-triage", false, "skip Haruspex triage even if a server is reachable")
	rootCmd.AddCommand(scanCmd)
}

func runScan(_ *cobra.Command, args []string) error {
	ctx := context.Background()

	var checkList []*checks.Check
	if scanChecksDir != "" {
		loaded, err := checks.LoadChecks(scanChecksDir)
		if err != nil {
			return fmt.Errorf("loading checks from %s: %w", scanChecksDir, err)
		}
		checkList = loaded
		if verbose {
			fmt.Fprintf(os.Stderr, "groma: loaded %d check(s) from %s\n", len(checkList), scanChecksDir)
		}
	}

	start := time.Now()
	var allFindings core.Findings
	for _, host := range args {
		findings, err := scanHost(ctx, host, checkList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "groma: %s: %v\n", host, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	duration := time.Since(start)

	if !scanNoTriage {
		// Fail-open: a single /health probe decides whether to spend any
		// further network calls at all (internal/haruspex.Ping) — an absent
		// server costs one short probe, not a timeout per finding, and never
		// removes a finding from the report (see package doc).
		haruspex.TriageFindings(ctx, haruspex.NewClient(scanHaruspexURL), allFindings)
	}

	report := reporting.NewReport(args, allFindings, duration)
	if err := writeReport(report); err != nil {
		return err
	}

	fail, count, err := evaluateGate(allFindings, scanFailOn)
	if err != nil {
		return err
	}
	if fail {
		threshold, _ := core.ParseSeverity(scanFailOn)
		return &gateError{Threshold: threshold, Count: count}
	}
	return nil
}

func writeReport(report *reporting.Report) error {
	w := os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", output, err)
		}
		defer f.Close()
		w = f
	}

	var writeErr error
	switch strings.ToLower(scanFormat) {
	case "json":
		writeErr = report.WriteJSON(w)
	case "sarif":
		writeErr = report.WriteSARIF(w)
	case "text", "":
		writeErr = report.WriteText(w)
	default:
		return fmt.Errorf("unknown --format %q (want text, json, or sarif)", scanFormat)
	}
	if writeErr != nil {
		return fmt.Errorf("writing report: %w", writeErr)
	}
	return nil
}

// scanHost discovers open ports (naabu if installed, else groma's native
// TCP-connect fallback), runs the seed protocol checks and any loaded
// YAML checks against whatever service data was identified, and returns
// every finding. Both discovery paths run the same legacyprotocol checks
// so a missing naabu install never silently drops coverage, only service
// fingerprinting (and therefore CVE-matching) depth.
func scanHost(ctx context.Context, host string, checkList []*checks.Check) (core.Findings, error) {
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	var findings core.Findings
	var portResults []discovery.PortResult
	var observations []checks.Observation

	n := naabu.New()
	if n.IsAvailable() {
		results, err := n.Scan(scanCtx, host, naabuOptionsFor())
		if err != nil {
			// A timeout or a non-zero exit still leaves naabu's results
			// (whatever it reported before stopping) usable — surface
			// the incompleteness, don't throw away real findings over it.
			fmt.Fprintf(os.Stderr, "groma: %s: %v\n", host, err)
		}
		for _, r := range results {
			findings = append(findings, r.ToFinding(host))
			portResults = append(portResults, discovery.PortResult{Port: r.Port, Open: true, Checked: true, Banner: r.Banner})
		}
		observations = checks.ObservationsFromNaabu(host, results)
	} else {
		if verbose {
			fmt.Fprintln(os.Stderr, "groma: naabu not found on $PATH, falling back to the native TCP-connect scanner (no service fingerprinting, so CVE checks have nothing to match on)")
		}
		ports, err := nativePortList()
		if err != nil {
			return nil, err
		}
		results, err := discovery.NewScanner().Scan(scanCtx, host, ports)
		if err != nil {
			// Same reasoning as the naabu branch: a context timeout still
			// returns every port the scanner actually reached. Only the
			// unreached tail (Checked=false) is genuinely unknown — the
			// legacyprotocol/checks passes below still run against what
			// was found, instead of the whole host being silently skipped.
			fmt.Fprintf(os.Stderr, "groma: %s: %v\n", host, err)
		}
		for _, r := range results {
			if r.Open {
				findings = append(findings, r.ToFinding(host))
			}
		}
		portResults = results
	}

	findings = append(findings, legacyprotocol.Detect(scanCtx, host, portResults)...)
	findings = append(findings, checks.Evaluate(checkList, observations)...)
	return findings, nil
}

func naabuOptionsFor() naabu.Options {
	opts := naabu.FullRangeOptions()
	if scanFast {
		opts = naabu.DefaultOptions()
	}
	if scanPorts != "" {
		opts.Ports = scanPorts
	}
	if scanRate > 0 {
		opts.Rate = scanRate
	}
	if scanConcurrency > 0 {
		opts.Concurrency = scanConcurrency
	}
	return opts
}

// nativePortList resolves the port set for the no-naabu fallback path.
// Unlike naabu (which takes an nmap-format port string directly), the
// native scanner needs an explicit []int, so --ports is parsed here.
func nativePortList() ([]int, error) {
	if scanPorts != "" {
		return parsePortSpec(scanPorts)
	}
	if scanFast {
		return nil, nil // native scanner's own DefaultPorts
	}
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports, nil
}

// parsePortSpec parses an nmap-format port spec ("80,443", "1-1000",
// "22,80-90,443") into an explicit port list.
func parsePortSpec(spec string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q: must be 1-65535 and ascending", part)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", p)
		}
		ports = append(ports, p)
	}
	return ports, nil
}
