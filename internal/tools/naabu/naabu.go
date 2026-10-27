// Package naabu wraps the projectdiscovery/naabu binary for fast port
// discovery — the SYN/CONNECT scanner in groma's pipeline. Service
// fingerprinting (identifying what's running on discovered ports) is
// handled by groma's native probe engine (internal/discovery/probe.go),
// which implements the same technique as nmap: sending protocol-specific
// probes and matching responses against known patterns.
//
// Why CLI wrapper instead of library import: naabu v2.6.1's
// pkg/fingerprint (the nmap-service-probes engine) exists only on the
// unreleased dev branch. The CLI is the stable interface; port scanning
// is what it does well. Service probing is done natively.
package naabu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/sysnet"
)

const (
	defaultConcurrency = 25
	maxConcurrency     = 1000

	// connectTimeoutMS is how long a connect probe waits for a handshake.
	// naabu's own default is 1000ms, which silently drops every port on a
	// high-latency or SYN-rate-limited host (the handshake simply doesn't
	// complete in time) and makes naabu report a live host as having zero
	// open ports. 3000ms matches nmap's behaviour of waiting out a slow RTT
	// and exceeds the native scanner's 2s, trading a longer tail wait on
	// filtered ports — bounded by the send rate — for not missing ports.
	// NOTE: fixed, not adaptive; a host slower than 3s still needs --timeout.
	connectTimeoutMS = 3000
	// connectRetries is deliberately 1, below naabu's own default of 3.
	// Each retry re-sends the entire non-responded port set, and on a
	// drop-heavy host (which never answers unused ports) that is ~65k extra
	// probes per retry: at naabu's default 3 the full-range connect scan
	// blows the per-host --timeout budget and returns PARTIAL results,
	// missing real open ports — the regression this value prevents. One
	// retry still rides out a single dropped handshake on a genuinely open
	// port; the native verification pass and the incomplete-scan warning
	// cover anything a lossier network still drops.
	connectRetries = 1
)

// Options configures a naabu run.
type Options struct {
	Ports    string
	TopPorts string

	ScanType string // "c" (connect) or "s" (SYN)

	Rate        int
	Concurrency int
	Retries     int
	TimeoutMS   int
	WarmUpTimeS int

	ExcludeCDN       bool
	DisplayCDN       bool
	ServiceVersion   bool
	ServiceDiscovery bool
	Verify           bool
	Passive          bool

	SmartScan           bool
	PredictionThreshold int

	ExcludeHosts  string
	ExcludePorts  string
	PortThreshold int

	CustomArgs []string
}

// DefaultOptions returns a fast triage baseline. Verify is on so that IF
// the caller switches to a SYN scan, every SYN-reported port is
// re-confirmed with a full connect handshake before groma believes it —
// SYN scans report a port open on a single unacknowledged probe and are
// the source of naabu's false positives on rate-limited/dropping
// networks. In the default connect mode -verify is a no-op (a completed
// handshake already proves the port open), so it never slows the common
// path (see BuildArgs).
func DefaultOptions() Options {
	return Options{
		ScanType:   "c",
		ExcludeCDN: true,
		Verify:     true,
		TimeoutMS:  connectTimeoutMS,
		Retries:    connectRetries,
	}
}

// FullRangeOptions returns an exhaustive 1-65535 sweep.
func FullRangeOptions() Options {
	return Options{
		Ports:      "1-65535",
		ScanType:   "c",
		ExcludeCDN: false,
		Verify:     true,
		TimeoutMS:  connectTimeoutMS,
		Retries:    connectRetries,
	}
}

// Result is one open port with service data.
type Result struct {
	Host      string
	IP        string
	Port      int
	Protocol  string
	IsCDN     bool
	CDNName   string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
	Banner    string
	CPEs      []string
}

// jsonLine mirrors naabu's -json output schema.
type jsonLine struct {
	Host      string   `json:"host"`
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Protocol  string   `json:"protocol"`
	IsCDNIP   bool     `json:"cdn"`
	CDNName   string   `json:"cdn-name"`
	Name      string   `json:"name"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	ExtraInfo string   `json:"extra_info"`
	Banner    string   `json:"banner"`
	CPEs      []string `json:"cpes"`
}

// ToFinding renders a Result as an informational core.Finding.
func (r Result) ToFinding(host string) *core.Finding {
	f := core.NewFinding("open_port", core.SeverityInfo)
	f.Tool = "naabu"
	f.Host, f.Port, f.Protocol = host, r.Port, r.Protocol
	f.Service = r.Service
	f.Product = r.Product
	f.Version = r.Version
	title := fmt.Sprintf("Port %d/%s open", r.Port, r.Protocol)
	if r.Product != "" {
		title = fmt.Sprintf("%s (%s %s)", title, r.Product, r.Version)
	}
	f.Title = title
	if r.Banner != "" {
		f.Evidence = "Banner: " + r.Banner
	}
	return f
}

// Naabu wraps the naabu binary.
type Naabu struct {
	binaryPath string
}

func New() *Naabu {
	return &Naabu{binaryPath: findNaabu()}
}

// findNaabu locates the naabu binary. It honours $PATH first, then falls
// back to the common Go install locations. The fallback matters under
// sudo: sudo's secure_path drops ~/go/bin, so a naabu installed with
// `go install` vanishes from $PATH and groma would silently degrade to
// the connect-only native scanner — ignoring a --scan-type syn request
// that only works via naabu, the exact reason to run as root. Resolving
// the invoking user's Go bin (via SUDO_USER) keeps SYN scans working.
func findNaabu() string {
	if path, err := exec.LookPath("naabu"); err == nil {
		return path
	}
	var dirs []string
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		dirs = append(dirs, gobin)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
			dirs = append(dirs, filepath.Join(u.HomeDir, "go", "bin"))
		}
	}
	dirs = append(dirs, "/usr/local/bin")
	for _, d := range dirs {
		p := filepath.Join(d, "naabu")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func (n *Naabu) Name() string      { return "naabu" }
func (n *Naabu) IsAvailable() bool { return n.binaryPath != "" }

// BuildArgs renders naabu CLI arguments. NOTE: -sV/-sD are intentionally
// omitted — they're broken in naabu 2.6.1. Service fingerprinting is
// done by groma's native probe engine instead.
func BuildArgs(host string, opts Options) []string {
	return buildArgs([]string{"-host", host}, opts)
}

// buildArgsList renders args that scan every host in a -list file in a
// single naabu process (see ScanTargets).
func buildArgsList(listPath string, opts Options) []string {
	return buildArgs([]string{"-list", listPath}, opts)
}

func buildArgs(target []string, opts Options) []string {
	args := append([]string{}, target...)
	args = append(args, "-json", "-silent", "-duc", "-Pn")

	if opts.Ports != "" {
		args = append(args, "-p", opts.Ports)
	} else if opts.TopPorts != "" {
		args = append(args, "-top-ports", opts.TopPorts)
	}
	scanType := opts.ScanType
	if scanType == "" {
		scanType = "c"
	}
	args = append(args, "-s", scanType)

	if opts.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(opts.Rate))
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = sysnet.RecommendedConcurrency(defaultConcurrency, maxConcurrency)
	}
	args = append(args, "-c", strconv.Itoa(concurrency))

	if opts.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(opts.Retries))
	}
	if opts.TimeoutMS > 0 {
		args = append(args, "-timeout", strconv.Itoa(opts.TimeoutMS))
	}
	if opts.WarmUpTimeS > 0 {
		args = append(args, "-warm-up-time", strconv.Itoa(opts.WarmUpTimeS))
	}
	if opts.ExcludeCDN {
		args = append(args, "-exclude-cdn")
	}
	if opts.DisplayCDN {
		args = append(args, "-display-cdn")
	}
	// -verify re-confirms each reported port with a full connect
	// handshake. It only matters for SYN scans (where a port is reported
	// open on a single unacknowledged probe); in connect mode the
	// handshake already happened, so passing it would just double the
	// work for no accuracy gain.
	if opts.Verify && scanType == "s" {
		args = append(args, "-verify")
	}
	if opts.Passive {
		args = append(args, "-passive")
	}
	if opts.SmartScan {
		args = append(args, "-ss")
		if opts.PredictionThreshold > 0 {
			args = append(args, "-pt", strconv.Itoa(opts.PredictionThreshold))
		}
	}
	if opts.ExcludeHosts != "" {
		args = append(args, "-exclude-hosts", opts.ExcludeHosts)
	}
	if opts.ExcludePorts != "" {
		args = append(args, "-exclude-ports", opts.ExcludePorts)
	}
	if opts.PortThreshold > 0 {
		args = append(args, "-port-threshold", strconv.Itoa(opts.PortThreshold))
	}
	args = append(args, opts.CustomArgs...)
	return args
}

// Scan runs naabu for port discovery against a single host and parses
// JSON output.
func (n *Naabu) Scan(ctx context.Context, host string, opts Options) ([]Result, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("naabu binary not found on $PATH")
	}
	return n.run(ctx, BuildArgs(host, opts))
}

// ScanTargets runs ONE naabu process over every host via a temp -list
// file. Running a single process rather than one-per-host is deliberate:
// naabu's own rate limiter and connection budget are per-process, so N
// parallel processes would multiply the packet rate against the target
// network by N — exactly the connection-flood behaviour the scanner is
// supposed to avoid.
func (n *Naabu) ScanTargets(ctx context.Context, hosts []string, opts Options) ([]Result, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("naabu binary not found on $PATH")
	}
	switch len(hosts) {
	case 0:
		return nil, nil
	case 1:
		return n.run(ctx, BuildArgs(hosts[0], opts))
	}
	f, err := os.CreateTemp("", "groma-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("naabu target list: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(strings.Join(hosts, "\n") + "\n"); err != nil {
		f.Close()
		return nil, fmt.Errorf("naabu target list: %w", err)
	}
	f.Close()
	return n.run(ctx, buildArgsList(f.Name(), opts))
}

// run executes naabu with the given args and parses whatever it emitted.
// Partial output on timeout or non-zero exit is kept and returned
// alongside the error, never discarded.
func (n *Naabu) run(ctx context.Context, args []string) ([]Result, error) {
	cmd := exec.CommandContext(ctx, n.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	results := ParseJSONLines(stdout.String())
	if runErr != nil {
		if ctx.Err() != nil {
			return results, fmt.Errorf("naabu scan incomplete (%d result(s)): %w", len(results), ctx.Err())
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return results, fmt.Errorf("naabu exited with code %d: %s",
				exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return results, fmt.Errorf("naabu: %w", runErr)
	}
	return results, nil
}

// ParseJSONLines converts naabu's -json stdout into Results, deduplicated
// by (host, ip, port, protocol). naabu emits each open port more than
// once — a scan pass and a retry/verify pass both print it — so without
// deduplication every port would appear two or more times in the report.
// When duplicates carry different data (one line has a banner or service
// name the other lacks), their non-empty fields are merged so nothing is
// lost to whichever copy happened to arrive first.
func ParseJSONLines(raw string) []Result {
	var out []Result
	if raw == "" {
		return out
	}
	index := map[string]int{} // dedup key -> position in out
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var jl jsonLine
		if err := json.Unmarshal([]byte(line), &jl); err != nil {
			continue
		}
		r := Result{
			Host: jl.Host, IP: jl.IP, Port: jl.Port, Protocol: jl.Protocol,
			IsCDN: jl.IsCDNIP, CDNName: jl.CDNName, Service: jl.Name,
			Product: jl.Product, Version: jl.Version, ExtraInfo: jl.ExtraInfo,
			Banner: jl.Banner, CPEs: jl.CPEs,
		}
		key := fmt.Sprintf("%s|%s|%d|%s", r.Host, r.IP, r.Port, r.Protocol)
		if pos, ok := index[key]; ok {
			mergeResult(&out[pos], r)
			continue
		}
		index[key] = len(out)
		out = append(out, r)
	}
	return out
}

// mergeResult folds any field set on src but missing on dst into dst, so
// a deduplicated port keeps service/banner data regardless of which
// duplicate line carried it.
func mergeResult(dst *Result, src Result) {
	if dst.Service == "" {
		dst.Service = src.Service
	}
	if dst.Product == "" {
		dst.Product = src.Product
	}
	if dst.Version == "" {
		dst.Version = src.Version
	}
	if dst.ExtraInfo == "" {
		dst.ExtraInfo = src.ExtraInfo
	}
	if dst.Banner == "" {
		dst.Banner = src.Banner
	}
	if len(dst.CPEs) == 0 {
		dst.CPEs = src.CPEs
	}
}
