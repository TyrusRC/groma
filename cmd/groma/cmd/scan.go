package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/TyrusRC/groma/internal/audit"
	"github.com/TyrusRC/groma/internal/checks"
	"github.com/TyrusRC/groma/internal/compliance"
	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/creds"
	"github.com/TyrusRC/groma/internal/detection/legacyprotocol"
	"github.com/TyrusRC/groma/internal/discovery"
	"github.com/TyrusRC/groma/internal/haruspex"
	"github.com/TyrusRC/groma/internal/nvd"
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

	scanSSHAudit           bool
	scanSSHPort            int
	scanSSHKnownHosts      string
	scanSSHInsecureHostKey bool

	scanCheckDefaultCreds bool

	scanCompliancePath string

	scanNVD      bool
	scanNVDKey   string
	scanNVDCache string
)

// svcCandidate is an open port paired with the best service-name guess
// groma has for it (naabu's fingerprint, or a well-known-port fallback
// when no fingerprint is available) — enough to decide whether a
// default-credential check applies, without needing full -sV data.
type svcCandidate struct {
	Port    int
	Service string
}

// guessServiceByPort maps well-known ports to service names for hosts
// scanned without naabu's -sV. Covers every service that has a
// registered default-credential checker in internal/creds, plus common
// services whose port number is unambiguous (modeled after nmap-services).
func guessServiceByPort(port int) string {
	return discovery.FingerprintByPort(port)
}

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
	scanCmd.Flags().BoolVar(&scanSSHAudit, "ssh-audit", false, "credentialed local check: SSH into the host and version-match its installed packages (needs GROMA_SSH_USER + GROMA_SSH_PASSWORD/GROMA_SSH_KEY env vars, or a running ssh-agent)")
	scanCmd.Flags().IntVar(&scanSSHPort, "ssh-port", 22, "SSH port for --ssh-audit")
	scanCmd.Flags().StringVar(&scanSSHKnownHosts, "ssh-known-hosts", "", "known_hosts path for --ssh-audit host key verification (default: ~/.ssh/known_hosts)")
	scanCmd.Flags().BoolVar(&scanSSHInsecureHostKey, "ssh-insecure-host-key", false, "skip SSH host key verification for --ssh-audit (opt-in, lab/first-connect targets only — vulnerable to MITM)")
	scanCmd.Flags().BoolVar(&scanCheckDefaultCreds, "check-default-creds", false, "bounded default-credential check for 35+ services (ssh, ftp, postgres, mysql, redis, mongodb, mssql, vnc, ldap, snmp, telnet, smtp, memcached, elasticsearch, grafana, jenkins, tomcat, rabbitmq, docker, k8s, consul, minio, portainer, harbor, argocd, jupyter, ollama, chromadb, airflow, and more); pair lists sourced from SecLists/Default-Credentials")
	scanCmd.Flags().StringVar(&scanCompliancePath, "compliance", "", "path to a Tenable .audit CIS/DISA-STIG compliance policy to run over SSH (needs the same GROMA_SSH_* credentials as --ssh-audit; CMD_EXEC and FILE_CHECK only — see internal/compliance)")
	scanCmd.Flags().BoolVar(&scanNVD, "nvd", false, "query the NIST NVD API for CVEs matching discovered service CPEs (live lookup, replaces hand-maintained YAML checks with 200k+ CVE coverage; set GROMA_NVD_API_KEY for higher rate limits)")
	scanCmd.Flags().StringVar(&scanNVDKey, "nvd-api-key", "", "NVD API key for higher rate limits (50 req/30s vs 5); also reads GROMA_NVD_API_KEY env var")
	scanCmd.Flags().StringVar(&scanNVDCache, "nvd-cache", "", "directory to cache NVD responses (default: $HOME/.cache/groma/nvd)")
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

	var compliancePolicy *compliance.Policy
	if scanCompliancePath != "" {
		raw, err := os.ReadFile(scanCompliancePath)
		if err != nil {
			return fmt.Errorf("reading --compliance policy %s: %w", scanCompliancePath, err)
		}
		compliancePolicy, err = compliance.Parse(string(raw))
		if err != nil {
			return fmt.Errorf("parsing --compliance policy %s: %w", scanCompliancePath, err)
		}
	}

	start := time.Now()
	var allFindings core.Findings
	for _, host := range args {
		findings, err := scanHost(ctx, host, checkList, compliancePolicy)
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
func scanHost(ctx context.Context, host string, checkList []*checks.Check, compliancePolicy *compliance.Policy) (core.Findings, error) {
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	var findings core.Findings
	var portResults []discovery.PortResult
	var observations []checks.Observation
	var svcCandidates []svcCandidate

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
			svc := strings.ToLower(r.Service)
			if svc == "" {
				svc = guessServiceByPort(r.Port)
			}
			svcCandidates = append(svcCandidates, svcCandidate{Port: r.Port, Service: svc})
		}
		observations = checks.ObservationsFromNaabu(host, results)
	} else {
		if verbose {
			fmt.Fprintln(os.Stderr, "groma: naabu not found on $PATH, falling back to native TCP-connect scanner with banner fingerprinting")
		}
		ports, err := nativePortList()
		if err != nil {
			return nil, err
		}
		results, err := discovery.NewScanner().Scan(scanCtx, host, ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "groma: %s: %v\n", host, err)
		}
		for _, r := range results {
			if r.Open {
				findings = append(findings, r.ToFinding(host))
				// Try banner fingerprint first, fall back to port guess.
				svc := ""
				if si := discovery.FingerprintBanner(r.Banner); si != nil {
					svc = strings.ToLower(si.Product)
				}
				if svc == "" {
					svc = guessServiceByPort(r.Port)
				}
				svcCandidates = append(svcCandidates, svcCandidate{Port: r.Port, Service: svc})
			}
		}
		portResults = results
		observations = checks.ObservationsFromBanners(host, portResults)
	}

	// Active service probing: if port discovery produced open ports but
	// no service observations (naabu's -sV unavailable, or native scanner
	// banners didn't match), run protocol-specific probes on each open
	// port. This is the nmap technique: NULL probe → HTTP probe → TLS
	// probe, matching responses against known service patterns.
	if len(observations) == 0 && len(portResults) > 0 {
		if verbose {
			open := 0
			for _, r := range portResults {
				if r.Open {
					open++
				}
			}
			fmt.Fprintf(os.Stderr, "groma: running active service probes on %d open port(s)\n", open)
		}
		svcMap := discovery.ProbeResults(scanCtx, host, portResults)
		// Rebuild observations and svcCandidates from probe results.
		for i, r := range portResults {
			if !r.Open {
				continue
			}
			if si, ok := svcMap[r.Port]; ok && si != nil {
				// Update the portResult banner for downstream use.
				if si.Product != "" {
					portResults[i].Banner = r.Banner
				}
			}
		}
		observations = checks.ObservationsFromProbes(host, portResults, svcMap)
		// Update svcCandidates with probed service names.
		for i, c := range svcCandidates {
			if si, ok := svcMap[c.Port]; ok && si != nil && si.Product != "" {
				svcCandidates[i].Service = strings.ToLower(si.Product)
			}
		}
	}

	findings = append(findings, legacyprotocol.Detect(scanCtx, host, portResults)...)
	findings = append(findings, checks.Evaluate(checkList, observations)...)

	if scanNVD {
		findings = append(findings, queryNVD(scanCtx, observations)...)
	}

	if scanCheckDefaultCreds {
		findings = append(findings, checkDefaultCreds(scanCtx, host, svcCandidates)...)
	}

	if scanSSHAudit {
		localObs, err := audit.Query(scanCtx, host, audit.CredentialsFromEnv(), audit.Options{
			Port:                      scanSSHPort,
			KnownHostsPath:            scanSSHKnownHosts,
			InsecureSkipHostKeyVerify: scanSSHInsecureHostKey,
		})
		if err != nil {
			// Fail open on the SSH audit specifically: a credential/network
			// problem on the credentialed pass must never drop the
			// unauthenticated findings already collected above.
			fmt.Fprintf(os.Stderr, "groma: %s: credentialed audit skipped: %v\n", host, err)
		} else {
			findings = append(findings, checks.Evaluate(checkList, localObs)...)
		}
	}

	if compliancePolicy != nil {
		complianceFindings, err := runCompliance(scanCtx, host, compliancePolicy)
		if err != nil {
			// Same fail-open posture as --ssh-audit: a credential/network
			// problem on the compliance pass must never drop the findings
			// already collected above.
			fmt.Fprintf(os.Stderr, "groma: %s: compliance check skipped: %v\n", host, err)
		} else {
			findings = append(findings, complianceFindings...)
		}
	}

	return findings, nil
}

// runCompliance opens its own SSH connection (sharing the same
// GROMA_SSH_* credential/host-key policy as --ssh-audit, but not the
// same TCP connection, since --ssh-audit may target a different port or
// not be enabled at all) and evaluates the compliance policy over it.
func runCompliance(ctx context.Context, host string, policy *compliance.Policy) (core.Findings, error) {
	client, err := audit.Dial(ctx, host, audit.CredentialsFromEnv(), audit.Options{
		Port:                      scanSSHPort,
		KnownHostsPath:            scanSSHKnownHosts,
		InsecureSkipHostKeyVerify: scanSSHInsecureHostKey,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	results, err := compliance.Evaluate(ctx, policy, &compliance.SSHExecutor{Client: client})
	if err != nil {
		return nil, fmt.Errorf("evaluating compliance policy: %w", err)
	}
	findings, unsupported, errored := compliance.ToFindings(host, results)
	if verbose {
		for _, r := range unsupported {
			fmt.Fprintf(os.Stderr, "groma: %s: compliance check %q (%s) not implemented, not scored\n", host, r.Item.Description, r.Item.Type)
		}
		for _, r := range errored {
			fmt.Fprintf(os.Stderr, "groma: %s: compliance check %q errored: %v\n", host, r.Item.Description, r.Err)
		}
	}
	return findings, nil
}

// checkDefaultCreds runs the bounded default-credential check (Rule-6-
// style: well-known vendor defaults only, stop on first hit, never a
// spray) against every distinct (port, service) candidate that has a
// registered checker. Unsupported services are silently skipped — see
// internal/creds.Checkers.
func checkDefaultCreds(ctx context.Context, host string, candidates []svcCandidate) core.Findings {
	var findings core.Findings
	seen := make(map[string]bool)
	for _, c := range candidates {
		if c.Service == "" {
			continue
		}
		key := fmt.Sprintf("%s:%d", c.Service, c.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		hit, err := creds.Check(ctx, c.Service, host, c.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "groma: %s: default-credential check on %s/%d: %v\n", host, c.Service, c.Port, err)
			continue
		}
		if hit == nil {
			continue
		}
		f := core.NewFinding("default-credentials-"+hit.Service, core.SeverityCritical)
		f.Tool = "groma"
		f.Host, f.Port, f.Protocol, f.Service = host, c.Port, "tcp", hit.Service
		f.Title = fmt.Sprintf("Default credentials accepted on %s", hit.Service)
		f.Description = fmt.Sprintf("The %s service accepted a well-known default credential. "+
			"An attacker with network access can authenticate using this publicly known pair.", hit.Service)
		f.Evidence = fmt.Sprintf("login %q with a well-known default password was accepted", hit.User)
		f.CWE = []string{"CWE-798"}
		f.Remediation = "Change the default credentials immediately and disable any default accounts that are not required."
		findings = append(findings, f)
	}
	return findings
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

// queryNVD looks up CVEs from the NIST NVD API for each observation
// that has a CPE. Deduplicates by CPE so the same service version is
// queried only once regardless of how many ports it appears on.
func queryNVD(ctx context.Context, observations []checks.Observation) core.Findings {
	apiKey := scanNVDKey
	if apiKey == "" {
		apiKey = os.Getenv("GROMA_NVD_API_KEY")
	}
	cacheDir := scanNVDCache
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			cacheDir = home + "/.cache/groma/nvd"
		}
	}
	client := nvd.NewClient(apiKey, cacheDir)

	type cpeObs struct {
		cpe string
		obs []checks.Observation
	}
	seen := map[string]*cpeObs{}
	for _, obs := range observations {
		for _, cpe := range obs.CPEs {
			// Convert CPE 2.2 URI (from naabu/banner fingerprint) to CPE
			// 2.3 format that NVD API 2.0 requires, splicing in the
			// observed version.
			cpe23 := nvd.CPE22to23(cpe, obs.Version)
			if _, ok := seen[cpe23]; !ok {
				seen[cpe23] = &cpeObs{cpe: cpe23}
			}
			seen[cpe23].obs = append(seen[cpe23].obs, obs)
		}
	}

	var findings core.Findings
	for _, co := range seen {
		matches, err := client.QueryByCPE(ctx, co.cpe)
		if err != nil {
			fmt.Fprintf(os.Stderr, "groma: nvd query for %s: %v\n", co.cpe, err)
			continue
		}
		if verbose && len(matches) > 0 {
			fmt.Fprintf(os.Stderr, "groma: nvd: %d CVE(s) for %s\n", len(matches), co.cpe)
		}
		for _, obs := range co.obs {
			findings = append(findings, nvd.ToFindings(
				obs.Host, obs.Port, obs.Protocol,
				obs.Product, obs.Product, obs.Version, matches,
			)...)
		}
	}
	return findings
}

