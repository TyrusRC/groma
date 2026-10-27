package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	embeddedchecks "github.com/TyrusRC/groma/checks"
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
	scanFailOn         string
	scanFailOnUnproven bool
	scanScanType        string
	scanPing            bool
	scanUDP             bool
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
	Port     int
	Protocol string // "tcp" | "udp"
	Service  string
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
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "exit code 2 if a finding at or above this severity is found (none|low|medium|high|critical); unproven version-based findings are excluded unless --fail-on-unproven")
	scanCmd.Flags().BoolVar(&scanFailOnUnproven, "fail-on-unproven", false, "also count unproven (version-based, possibly backport-patched) findings toward --fail-on")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout budget per host (the naabu batch gets host-count × this)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 0, "worker concurrency passed to naabu (0 = auto, ulimit-aware)")
	scanCmd.Flags().IntVar(&scanHostConcurrency, "host-concurrency", 0, "how many hosts to analyse in parallel (0 = auto); the native scanner's connection budget is bounded globally and separately")
	scanCmd.Flags().StringVar(&scanTargetFile, "target-file", "", "read additional targets (one host/CIDR/range per line; '-' reads stdin) in addition to any given as arguments")
	scanCmd.Flags().StringVar(&scanScanType, "scan-type", "auto", "naabu scan type: auto (syn when run as root, else connect), connect, or syn")
	scanCmd.Flags().BoolVar(&scanPing, "ping", false, "host discovery: skip targets that don't answer a quick TCP probe (faster on sparse subnets; a host firewalled on all common ports will be skipped, so off by default)")
	scanCmd.Flags().BoolVar(&scanUDP, "udp", true, "probe common UDP services (DNS, NTP, SNMP) with protocol-specific probes (on by default; only ports that give a valid reply are reported — no blind UDP sweep)")
	scanCmd.Flags().IntVar(&scanRate, "rate", 0, "packets/sec rate limit passed to naabu (0 = naabu's own default)")
	scanCmd.Flags().StringVar(&scanHaruspexURL, "haruspex-url", "", "Haruspex decision server base URL for finding triage (default: http://127.0.0.1:3000)")
	scanCmd.Flags().BoolVar(&scanNoTriage, "no-triage", false, "skip Haruspex triage even if a server is reachable")
	scanCmd.Flags().BoolVar(&scanSSHAudit, "ssh-audit", false, "credentialed local check: SSH into the host and version-match its installed packages (needs GROMA_SSH_USER + GROMA_SSH_PASSWORD/GROMA_SSH_KEY env vars, or a running ssh-agent)")
	scanCmd.Flags().IntVar(&scanSSHPort, "ssh-port", 22, "SSH port for --ssh-audit")
	scanCmd.Flags().StringVar(&scanSSHKnownHosts, "ssh-known-hosts", "", "known_hosts path for --ssh-audit host key verification (default: ~/.ssh/known_hosts)")
	scanCmd.Flags().BoolVar(&scanSSHInsecureHostKey, "ssh-insecure-host-key", false, "skip SSH host key verification for --ssh-audit (opt-in, lab/first-connect targets only — vulnerable to MITM)")
	scanCmd.Flags().BoolVar(&scanCheckDefaultCreds, "check-default-creds", true, "bounded default-credential check for discovered services (on by default; --check-default-creds=false to skip); well-known vendor defaults only, stops on first hit, never sprays")
	scanCmd.Flags().StringVar(&scanCompliancePath, "compliance", "", "path to a Tenable .audit CIS/DISA-STIG compliance policy to run over SSH (needs the same GROMA_SSH_* credentials as --ssh-audit; CMD_EXEC and FILE_CHECK only — see internal/compliance)")
	scanCmd.Flags().BoolVar(&scanNVD, "nvd", true, "query the NIST NVD API for CVEs matching discovered service CPEs (on by default, fail-open and cached; --nvd=false to skip for a fully offline scan; set GROMA_NVD_API_KEY for higher rate limits)")
	scanCmd.Flags().StringVar(&scanNVDKey, "nvd-api-key", "", "NVD API key for higher rate limits (50 req/30s vs 5); also reads GROMA_NVD_API_KEY env var")
	scanCmd.Flags().StringVar(&scanNVDCache, "nvd-cache", "", "directory to cache NVD responses (default: $HOME/.cache/groma/nvd)")

	// Keep `groma scan --help` short. Everything groma does — port +
	// service discovery, bundled CVE checks, NVD, default-credential
	// checks, UDP probing, and a credentialed audit when GROMA_SSH_* is
	// set — runs automatically from just a target. The flags below are
	// overrides for advanced use; they still work, they're just hidden
	// from the default help so a new user never has to read them.
	for _, hidden := range []string{
		"scan-type", "udp", "nvd", "check-default-creds",
		"ssh-audit", "ssh-port", "ssh-known-hosts", "ssh-insecure-host-key",
		"checks", "concurrency", "host-concurrency", "rate", "timeout",
		"nvd-api-key", "nvd-cache", "haruspex-url", "no-triage",
		"fail-on-unproven",
	} {
		_ = scanCmd.Flags().MarkHidden(hidden)
	}
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	resolveAutoDefaults(cmd)

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
	} else {
		// No --checks given: use the CVE checks bundled into the binary so
		// a bare `groma scan <target>` still matches known vulnerabilities
		// with zero setup.
		loaded, err := checks.LoadChecksFS(embeddedchecks.Examples, "examples")
		if err != nil {
			return fmt.Errorf("loading bundled checks: %w", err)
		}
		checkList = loaded
		if verbose {
			fmt.Fprintf(os.Stderr, "groma: loaded %d bundled check(s)\n", len(checkList))
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
		fmt.Fprintf(os.Stderr, "groma: %d host(s) to scan\n", len(hosts))
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

	// Always warn on an incomplete scan, not only under a gate: a run that
	// hit the --timeout budget or was rate-limited/dropped by the target
	// produces a report indistinguishable from a genuinely clean host, and
	// silently presenting "no open ports" for a scan that never finished is
	// the one false negative a scanner must never hand the user unflagged.
	if incomplete {
		fmt.Fprintln(os.Stderr, "groma: WARNING: scan did not complete — results may be partial. A host exceeded the --timeout budget or the target rate-limited/dropped probes; treat an empty or small result as unverified. Re-run with a higher --timeout, fewer targets at once, or (as root) --scan-type syn.")
	}

	fail, count, err := evaluateGate(allFindings, scanFailOn, scanFailOnUnproven)
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

	// Color only when writing to an interactive terminal (not a file or a
	// pipe) and the operator hasn't opted out via NO_COLOR.
	report.Color = output == "" && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)

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
	if scanPing {
		live := discovery.FilterAlive(ctx, hosts, 1*time.Second, hostPoolSize(len(hosts)))
		if verbose || len(live) != len(hosts) {
			fmt.Fprintf(os.Stderr, "groma: host discovery: %d/%d host(s) responded\n", len(live), len(hosts))
		}
		hosts = live
		if len(hosts) == 0 {
			return nil, false
		}
	}

	var (
		discovered map[string]*hostDiscovery
		incomplete bool
	)
	if n := naabu.New(); n.IsAvailable() {
		discovered, incomplete = discoverWithNaabu(ctx, n, hosts)
		discovered, incomplete = verifyNaabuMisses(ctx, hosts, discovered, incomplete)
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

	// Mark version-based findings on distro-packaged hosts as unproven:
	// distros backport security fixes without bumping the upstream version,
	// so a version match there is a lead, not a confirmed vulnerability.
	distroByHost := map[string]string{}
	for host, hd := range discovered {
		distroByHost[host] = detectDistro(hd.portResults)
	}
	for _, f := range all {
		// Credentialed-audit findings (Protocol "local") read the real
		// installed package version, not an unauthenticated banner, so the
		// backport caveat does not apply — leaving them confirmed is exactly
		// how --ssh-audit resolves a host the gate would otherwise skip.
		if f.Protocol == "local" {
			continue
		}
		if distro := distroByHost[f.Host]; distro != "" && isVersionBased(f) {
			markBackportUnproven(f, distro)
		}
	}

	// Collapse the same CVE reported by both a bundled check and NVD.
	return all.Dedup(), incomplete
}

// isVersionBased reports whether a finding was derived purely from a
// service's reported version (a bundled CVE check or an NVD CPE match),
// as opposed to an actively proven issue (open port, accepted default
// credential). Only version-based findings are subject to the distro
// backport caveat.
func isVersionBased(f *core.Finding) bool {
	return f.Tool == "nvd" || strings.HasPrefix(strings.ToUpper(f.Type), "CVE")
}

// markBackportUnproven flags a version-based finding as unconfirmed and
// records why, without removing it — the fix may genuinely be absent. It
// sets the dedicated VersionUnconfirmed field (which the gate keys off)
// rather than Triage, because the Haruspex triage step runs afterwards
// and would overwrite Triage, silently re-arming the gate.
func markBackportUnproven(f *core.Finding, distro string) {
	f.VersionUnconfirmed = true
	note := fmt.Sprintf("version-based match on a %s-packaged service; the distro may have backported the fix without changing the version — confirm with --ssh-audit", distro)
	if f.Evidence == "" {
		f.Evidence = note
	} else {
		f.Evidence += " — " + note
	}
}

// canonHost returns a stable key for matching a scanner-reported address
// against our target list. IP literals are normalised through netip so
// differing textual forms (IPv6 zero-compression, casing, brackets) still
// match; hostnames pass through unchanged.
func canonHost(s string) string {
	t := strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	if a, err := netip.ParseAddr(t); err == nil {
		return a.String()
	}
	return s
}

// detectDistro returns the OS distribution a host's services appear to be
// packaged by (from banners like "Apache/2.4.7 (Ubuntu)" or
// "OpenSSH_6.6.1p1 Ubuntu-..."), or "" if none is evident.
func detectDistro(results []discovery.PortResult) string {
	for _, r := range results {
		if d := distroFromBanner(r.Banner); d != "" {
			return d
		}
	}
	return ""
}

func distroFromBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(b, "debian"), strings.Contains(b, "+deb"):
		return "Debian"
	case strings.Contains(b, "(red hat)"), strings.Contains(b, "centos"),
		strings.Contains(b, ".el6"), strings.Contains(b, ".el7"),
		strings.Contains(b, ".el8"), strings.Contains(b, ".el9"):
		return "Red Hat/CentOS"
	case strings.Contains(b, "fedora"), strings.Contains(b, ".fc"):
		return "Fedora"
	default:
		return ""
	}
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
	// Match naabu's reported address back to our target spec by canonical
	// form: an IPv6 target expands to netip's canonical text but naabu may
	// echo it bracketed, zero-expanded or upper-cased, and a raw string
	// compare would bucket the result under a key the analysis loop (which
	// ranges over hosts) never reads — silently dropping every port.
	known := make(map[string]string, len(hosts))
	for _, h := range hosts {
		known[canonHost(h)] = h
	}
	for _, r := range results {
		key := r.Host
		if orig, ok := known[canonHost(r.Host)]; ok {
			key = orig
		} else if orig, ok := known[canonHost(r.IP)]; ok {
			key = orig
		}
		byHost[key] = append(byHost[key], r)
	}

	// Build each host's discovery and run its active service/UDP probes in
	// a bounded pool. naabu already found the ports in one process; the
	// per-host probing that follows is network-bound, so running it
	// serially would make a subnet scan take host-count × the probe time —
	// the native path parallelizes the identical work, and so must this.
	out := make(map[string]*hostDiscovery, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	pool := make(chan struct{}, hostPoolSize(len(hosts)))
	for _, host := range hosts {
		wg.Add(1)
		pool <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-pool }()

			hd := &hostDiscovery{}
			for _, r := range byHost[host] {
				hd.findings = append(hd.findings, r.ToFinding(host))
				hd.portResults = append(hd.portResults, discovery.PortResult{Port: r.Port, Open: true, Checked: true, Banner: r.Banner})
				svc := strings.ToLower(r.Service)
				if svc == "" {
					svc = guessServiceByPort(r.Port)
				}
				hd.svcCandidates = append(hd.svcCandidates, svcCandidate{Port: r.Port, Protocol: "tcp", Service: svc})
			}
			hd.observations = checks.ObservationsFromNaabu(host, byHost[host])
			enrichWithProbes(scanCtx, host, hd)
			if scanUDP {
				addUDPServices(scanCtx, host, hd)
			}

			mu.Lock()
			out[host] = hd
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return out, incomplete
}

// verifyNaabuMisses re-scans, with the native connect scanner, any host
// naabu reported no open ports on. naabu is non-deterministic on
// high-latency or SYN-rate-limiting hosts: it can exit 0 having found
// nothing on a host that is actually up (observed live: the same host
// returning 0, then 3, open ports across back-to-back runs), and groma
// would otherwise report that live host as clean — the one false negative
// a security scanner must never produce. The native pass uses a longer
// timeout and retries, so it catches what naabu's faster probes dropped.
//
// It is gated on a liveness probe so a genuinely empty subnet is not
// re-scanned wholesale: only hosts that answer a common-port knock (with
// a generous timeout, so a slow host is not mistaken for dead) are
// re-scanned. NOTE: a host whose only open ports are unusual ones not in
// the liveness set will still be judged down here — the inherent limit of
// knock-based liveness, shared with nmap's default host discovery.
func verifyNaabuMisses(ctx context.Context, hosts []string, discovered map[string]*hostDiscovery, incomplete bool) (map[string]*hostDiscovery, bool) {
	var empty []string
	for _, h := range hosts {
		if hd := discovered[h]; hd == nil || countOpen(hd.portResults) == 0 {
			empty = append(empty, h)
		}
	}
	if len(empty) == 0 {
		return discovered, incomplete
	}
	alive := discovery.FilterAlive(ctx, empty, 3*time.Second, hostPoolSize(len(empty)))
	if len(alive) == 0 {
		return discovered, incomplete
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "groma: naabu found no ports on %d live host(s); verifying with the native scanner\n", len(alive))
	}
	native, ninc := discoverNative(ctx, alive)
	for h, hd := range native {
		if hd != nil && countOpen(hd.portResults) > 0 {
			discovered[h] = hd
		}
	}
	return discovered, incomplete || ninc
}

// countOpen returns how many of results are open ports.
func countOpen(results []discovery.PortResult) int {
	n := 0
	for _, r := range results {
		if r.Open {
			n++
		}
	}
	return n
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
				hd.svcCandidates = append(hd.svcCandidates, svcCandidate{Port: r.Port, Protocol: "tcp", Service: svc})
			}
			hd.observations = checks.ObservationsFromBanners(host, results)
			enrichWithProbes(scanCtx, host, hd)
			if scanUDP {
				addUDPServices(scanCtx, host, hd)
			}

			mu.Lock()
			out[host] = hd
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return out, incomplete
}

// addUDPServices probes common UDP services and records each one that
// gives a valid protocol reply as an open udp port, feeding it to the
// credential checker too (so e.g. SNMP default-community checks can run).
func addUDPServices(ctx context.Context, host string, hd *hostDiscovery) {
	for _, u := range discovery.ProbeUDP(ctx, host, 2*time.Second, nil) {
		f := core.NewFinding("open_port", core.SeverityInfo)
		f.Tool = "groma"
		f.Host, f.Port, f.Protocol, f.Service = host, u.Port, "udp", u.Service
		f.Title = fmt.Sprintf("Port %d/udp open (%s)", u.Port, u.Service)
		hd.findings = append(hd.findings, f)
		hd.svcCandidates = append(hd.svcCandidates, svcCandidate{Port: u.Port, Protocol: "udp", Service: u.Service})
	}
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
		proto := c.Protocol
		if proto == "" {
			proto = "tcp"
		}
		// Key on protocol too: the same service on the same port over tcp and
		// udp (e.g. a tcp/udp 161 pair) are distinct targets to check.
		key := fmt.Sprintf("%s:%d/%s", c.Service, c.Port, proto)
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
		f.Host, f.Port, f.Protocol, f.Service = host, c.Port, proto, hit.Service
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

// resolveAutoDefaults adapts the scan to its environment so a bare
// `groma scan <target>` does the right thing with no flags: pick the
// fastest scan type the privileges allow, and run the credentialed audit
// automatically when SSH credentials are present in the environment.
func resolveAutoDefaults(cmd *cobra.Command) {
	if strings.EqualFold(scanScanType, "auto") {
		if os.Geteuid() == 0 {
			scanScanType = "syn"
		} else {
			scanScanType = "connect"
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "groma: scan-type auto → %s\n", scanScanType)
		}
	}

	// A GROMA_SSH_USER in the environment is a clear signal the operator
	// wants a credentialed audit; enable it automatically (it also
	// confirms version-based findings against real package versions,
	// resolving the "unproven" ones) unless they set the flag themselves.
	if !cmd.Flags().Changed("ssh-audit") && os.Getenv("GROMA_SSH_USER") != "" {
		scanSSHAudit = true
		if verbose {
			fmt.Fprintln(os.Stderr, "groma: GROMA_SSH_USER set → running credentialed SSH audit")
		}
	}
}

// isTerminal reports whether f is an interactive terminal (a character
// device), using only the standard library so groma keeps no extra
// dependency just to decide whether to emit color.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
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
		// Without a concrete version the CPE collapses to a product
		// wildcard, which makes NVD return every CVE ever filed against
		// that product regardless of version — pure false positives. A
		// version is required before we assert any CVE.
		if strings.TrimSpace(obs.Version) == "" {
			if verbose {
				fmt.Fprintf(os.Stderr, "groma: nvd: skipping %s on %s:%d (no version identified)\n", obs.Product, obs.Host, obs.Port)
			}
			continue
		}
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

