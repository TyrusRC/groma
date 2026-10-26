package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/TyrusRC/groma/internal/targets"
	"github.com/TyrusRC/groma/internal/tools/naabu"
)

var (
	scanPorts       string
	scanFast        bool
	scanChecksDir   string
	scanFormat      string
	scanFailOn      string
	scanScanType        string
	scanTimeout         time.Duration
	scanConcurrency     int
	scanHostConcurrency int
	scanTargetFile      string
	scanRate            int
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
	Use:   "scan <host|CIDR|range> [target...]",
	Short: "Scan hosts, subnets (CIDR), or IP ranges for open ports, services, and known vulnerabilities",
	Args:  cobra.ArbitraryArgs,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanPorts, "ports", "", "explicit port list/range (nmap format, e.g. \"80,443\" or \"1-1000\"); overrides --fast")
	scanCmd.Flags().BoolVar(&scanFast, "fast", false, "scan only a top-N ports subset instead of the full 1-65535 default (quicker, NOT exhaustive)")
	scanCmd.Flags().StringVar(&scanChecksDir, "checks", "", "directory of check YAML files to load and match (default: none — port/service discovery only)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "output format: text, json, sarif")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "exit code 2 if a finding at or above this severity is found (none|low|medium|high|critical)")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout budget per host (the naabu batch gets host-count × this)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 0, "worker concurrency passed to naabu (0 = auto, ulimit-aware)")
	scanCmd.Flags().IntVar(&scanHostConcurrency, "host-concurrency", 0, "how many hosts to analyse in parallel (0 = auto); the native scanner's connection budget is bounded globally and separately")
	scanCmd.Flags().StringVar(&scanTargetFile, "target-file", "", "read additional targets (one host/CIDR/range per line; '-' reads stdin) in addition to any given as arguments")
	scanCmd.Flags().StringVar(&scanScanType, "scan-type", "connect", "naabu scan type: connect (no privileges, FP-free) or syn (faster, needs root/CAP_NET_RAW; auto-verified to kill SYN false positives)")
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

	specs := append([]string{}, args...)
	if scanTargetFile != "" {
		fileSpecs, err := readTargetFile(scanTargetFile)
		if err != nil {
			return err
		}
		specs = append(specs, fileSpecs...)
	}
	if len(specs) == 0 {
		return fmt.Errorf("no targets given: pass a host/CIDR/range argument or --target-file")
	}

	hosts, err := targets.Expand(specs)
	if err != nil {
		return fmt.Errorf("resolving targets: %w", err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no targets to scan")
	}
	if verbose || len(hosts) > 1 {
		fmt.Fprintf(os.Stderr, "groma: %d target(s) to scan\n", len(hosts))
	}

	start := time.Now()
	allFindings, incomplete := scanTargets(ctx, hosts, checkList, compliancePolicy)
	duration := time.Since(start)

	if !scanNoTriage {
		// Fail-open: a single /health probe decides whether to spend any
		// further network calls at all (internal/haruspex.Ping) — an absent
		// server costs one short probe, not a timeout per finding, and never
		// removes a finding from the report (see package doc).
		haruspex.TriageFindings(ctx, haruspex.NewClient(scanHaruspexURL), allFindings)
	}

	report := reporting.NewReport(specs, allFindings, duration)
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
	// Fail closed: if the scan did not finish, a clean gate result is not
	// trustworthy — an unscanned host could be the one with a critical
	// finding. Only matters when a gate is actually in use (--fail-on).
	if incomplete && scanFailOn != "" {
		return fmt.Errorf("scan incomplete: results may be missing, failing the gate closed (raise --timeout or narrow the scan)")
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

// hostDiscovery is the per-host result of the port-discovery phase: the
// open ports found, the service observations fed to the CVE engine, the
// (service, port) candidates fed to the default-credential checker, and
// the informational open_port findings.
type hostDiscovery struct {
	findings      core.Findings
	portResults   []discovery.PortResult
	observations  []checks.Observation
	svcCandidates []svcCandidate
}

// scanTargets runs the whole pipeline over every host and returns all
// findings in stable host order (regardless of completion order).
//
// It runs in two phases so each stays correctly resource-bounded:
//  1. Discovery. With naabu installed, ONE process scans every host (its
//     own rate limiter stays authoritative). Without it, the native
//     TCP-connect scanner runs across hosts sharing a single global
//     connection budget, so total in-flight connections never scale with
//     the number of hosts.
//  2. Analysis. Per-host service probing, CVE matching, credential checks
//     and compliance run in a bounded worker pool.
// scanTargets runs the whole pipeline and returns every finding in stable
// host order plus an incomplete flag. incomplete is true when discovery
// did not finish for at least one host (a naabu timeout/error, or native
// ports left unreached); the caller fails a CI gate closed on it rather
// than reporting a truncated scan as clean.
func scanTargets(ctx context.Context, hosts []string, checkList []*checks.Check, compliancePolicy *compliance.Policy) (core.Findings, bool) {
	var (
		discovered map[string]*hostDiscovery
		incomplete bool
	)
	if n := naabu.New(); n.IsAvailable() {
		discovered, incomplete = discoverWithNaabu(ctx, n, hosts)
	} else {
		if verbose {
			fmt.Fprintln(os.Stderr, "groma: naabu not found on $PATH, falling back to native TCP-connect scanner with banner fingerprinting")
		}
		discovered, incomplete = discoverNative(ctx, hosts)
	}

	// Phase 2: analysis, bounded across hosts. Results land in a slice
	// indexed by host order so output is deterministic.
	perHost := make([]core.Findings, len(hosts))
	var done int64
	pool := make(chan struct{}, hostPoolSize(len(hosts)))
	var wg sync.WaitGroup
	for i, host := range hosts {
		hd := discovered[host]
		if hd == nil {
			continue
		}
		wg.Add(1)
		pool <- struct{}{}
		go func(i int, host string, hd *hostDiscovery) {
			defer wg.Done()
			defer func() { <-pool }()
			perHost[i] = analyzeHost(ctx, host, hd, checkList, compliancePolicy)
			if n := atomic.AddInt64(&done, 1); len(hosts) > 1 {
				fmt.Fprintf(os.Stderr, "groma: analyzed %d/%d host(s)\r", n, len(hosts))
			}
		}(i, host, hd)
	}
	wg.Wait()
	if len(hosts) > 1 {
		fmt.Fprintln(os.Stderr)
	}

	var all core.Findings
	for _, f := range perHost {
		all = append(all, f...)
	}

	// NVD runs once for the whole scan, not per host: a single client
	// shares one rate-limit budget (the NVD free tier is 5 req/30s), and
	// deduplicating CPEs across every host avoids re-querying a version
	// that appears on many hosts. Running it inside the per-host pool
	// would spin up one unsynchronized client per host and get throttled.
	if scanNVD {
		var allObs []checks.Observation
		for _, host := range hosts {
			if hd := discovered[host]; hd != nil {
				allObs = append(allObs, hd.observations...)
			}
		}
		all = append(all, queryNVD(ctx, allObs)...)
	}

	return all, incomplete
}

// discoverWithNaabu runs one naabu process over every host and groups the
// results back per host. The second return value is true if naabu did not
// finish (timeout or non-zero exit), so the scan is incomplete.
func discoverWithNaabu(ctx context.Context, n *naabu.Naabu, hosts []string) (map[string]*hostDiscovery, bool) {
	// --timeout is a per-host budget. One naabu process scans every host,
	// so the batch gets host-count × that budget — otherwise a subnet
	// scan would silently truncate at one host's worth of time and report
	// unscanned hosts as clean, the exact false-negative a CI gate must
	// never produce.
	timeout := time.Duration(len(hosts)) * scanTimeout
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	incomplete := false
	results, err := n.ScanTargets(scanCtx, hosts, naabuOptionsFor())
	if err != nil {
		// Partial results on timeout/non-zero exit are still usable —
		// surface the incompleteness, don't discard real findings.
		fmt.Fprintf(os.Stderr, "groma: %v\n", err)
		incomplete = true
	}

	// naabu reports the target it was given in the Host field (IP when
	// scanned by IP); fall back to IP so every result lands somewhere.
	byHost := map[string][]naabu.Result{}
	known := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		known[h] = struct{}{}
	}
	for _, r := range results {
		key := r.Host
		if _, ok := known[key]; !ok {
			if _, ok := known[r.IP]; ok {
				key = r.IP
			}
		}
		byHost[key] = append(byHost[key], r)
	}

	out := make(map[string]*hostDiscovery, len(hosts))
	for _, host := range hosts {
		hd := &hostDiscovery{}
		for _, r := range byHost[host] {
			hd.findings = append(hd.findings, r.ToFinding(host))
			hd.portResults = append(hd.portResults, discovery.PortResult{Port: r.Port, Open: true, Checked: true, Banner: r.Banner})
			svc := strings.ToLower(r.Service)
			if svc == "" {
				svc = guessServiceByPort(r.Port)
			}
			hd.svcCandidates = append(hd.svcCandidates, svcCandidate{Port: r.Port, Service: svc})
		}
		hd.observations = checks.ObservationsFromNaabu(host, byHost[host])
		enrichWithProbes(scanCtx, host, hd)
		out[host] = hd
	}
	return out, incomplete
}

// discoverNative scans every host with the native TCP-connect scanner,
// sharing ONE global connection budget across all hosts so the total
// connection count is bounded regardless of how many hosts are scanned.
// The second return value is true if any host's scan left ports
// unreached (context ended early), so the scan is incomplete.
func discoverNative(ctx context.Context, hosts []string) (map[string]*hostDiscovery, bool) {
	ports, err := nativePortList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "groma: %v\n", err)
		return map[string]*hostDiscovery{}, true
	}

	base := discovery.NewScanner()
	gate := make(chan struct{}, max(1, base.Concurrency))

	out := make(map[string]*hostDiscovery, len(hosts))
	var mu sync.Mutex
	var incomplete bool
	var wg sync.WaitGroup
	pool := make(chan struct{}, hostPoolSize(len(hosts)))
	for _, host := range hosts {
		wg.Add(1)
		pool <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-pool }()

			scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
			defer cancel()

			sc := &discovery.Scanner{
				DialTimeout: base.DialTimeout,
				BannerWait:  base.BannerWait,
				Retries:     base.Retries,
				Gate:        gate, // shared global budget
			}
			results, err := sc.Scan(scanCtx, host, ports)
			if err != nil {
				fmt.Fprintf(os.Stderr, "groma: %s: %v\n", host, err)
				mu.Lock()
				incomplete = true
				mu.Unlock()
			}
			hd := &hostDiscovery{portResults: results}
			for _, r := range results {
				if !r.Open {
					continue
				}
				hd.findings = append(hd.findings, r.ToFinding(host))
				svc := ""
				if si := discovery.FingerprintBanner(r.Banner); si != nil {
					svc = strings.ToLower(si.Product)
				}
				if svc == "" {
					svc = guessServiceByPort(r.Port)
				}
				hd.svcCandidates = append(hd.svcCandidates, svcCandidate{Port: r.Port, Service: svc})
			}
			hd.observations = checks.ObservationsFromBanners(host, results)
			enrichWithProbes(scanCtx, host, hd)

			mu.Lock()
			out[host] = hd
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return out, incomplete
}

// enrichWithProbes runs active service probes (nmap technique: NULL →
// HTTP → TLS) when discovery found open ports but no service
// observations, and folds the identified services back into the
// observations and credential candidates.
func enrichWithProbes(ctx context.Context, host string, hd *hostDiscovery) {
	if len(hd.observations) != 0 || len(hd.portResults) == 0 {
		return
	}
	open := 0
	for _, r := range hd.portResults {
		if r.Open {
			open++
		}
	}
	if open == 0 {
		return
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "groma: %s: active service probes on %d open port(s)\n", host, open)
	}
	svcMap := discovery.ProbeResults(ctx, host, hd.portResults)
	hd.observations = checks.ObservationsFromProbes(host, hd.portResults, svcMap)
	for i, c := range hd.svcCandidates {
		if si, ok := svcMap[c.Port]; ok && si != nil && si.Product != "" {
			hd.svcCandidates[i].Service = strings.ToLower(si.Product)
		}
	}
}

// analyzeHost runs the post-discovery pipeline for one host: legacy
// protocol checks, YAML CVE matching, optional NVD lookup, default-
// credential checks, credentialed SSH audit and compliance.
func analyzeHost(ctx context.Context, host string, hd *hostDiscovery, checkList []*checks.Check, compliancePolicy *compliance.Policy) core.Findings {
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	findings := append(core.Findings{}, hd.findings...)
	findings = append(findings, legacyprotocol.Detect(scanCtx, host, hd.portResults)...)
	findings = append(findings, checks.Evaluate(checkList, hd.observations)...)

	// NVD is deliberately NOT run here — it runs once for the whole scan
	// in scanTargets so one rate-limit budget covers every host.

	if scanCheckDefaultCreds {
		findings = append(findings, checkDefaultCreds(scanCtx, host, hd.svcCandidates)...)
	}

	if scanSSHAudit {
		localObs, err := audit.Query(scanCtx, host, audit.CredentialsFromEnv(), audit.Options{
			Port:                      scanSSHPort,
			KnownHostsPath:            scanSSHKnownHosts,
			InsecureSkipHostKeyVerify: scanSSHInsecureHostKey,
		})
		if err != nil {
			// Fail open: a credential/network problem on the credentialed
			// pass must never drop the unauthenticated findings above.
			fmt.Fprintf(os.Stderr, "groma: %s: credentialed audit skipped: %v\n", host, err)
		} else {
			findings = append(findings, checks.Evaluate(checkList, localObs)...)
		}
	}

	if compliancePolicy != nil {
		complianceFindings, err := runCompliance(scanCtx, host, compliancePolicy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "groma: %s: compliance check skipped: %v\n", host, err)
		} else {
			findings = append(findings, complianceFindings...)
		}
	}

	return findings
}

// hostPoolSize bounds how many hosts are analysed (and, on the native
// path, discovered) concurrently. The native scanner's connection budget
// is gated globally and separately, so this only controls per-host work
// like probing and credential checks.
func hostPoolSize(n int) int {
	if scanHostConcurrency > 0 {
		return scanHostConcurrency
	}
	const auto = 20
	if n < auto {
		return max(1, n)
	}
	return auto
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
	switch strings.ToLower(scanScanType) {
	case "syn", "s":
		opts.ScanType = "s"
	case "connect", "c", "":
		opts.ScanType = "c"
	}
	if scanRate > 0 {
		opts.Rate = scanRate
	}
	if scanConcurrency > 0 {
		opts.Concurrency = scanConcurrency
	}
	return opts
}

// readTargetFile reads target specs (one per line) from a file, or from
// stdin when path is "-". Blank lines and '#' comments are ignored.
func readTargetFile(path string) ([]string, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("reading --target-file %s: %w", path, err)
		}
		defer f.Close()
	}
	var specs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading --target-file %s: %w", path, err)
	}
	return specs, nil
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

