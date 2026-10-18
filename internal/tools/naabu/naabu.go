// Package naabu wraps the projectdiscovery/naabu binary — the fast,
// wide-range port-discovery pass in groma's pipeline. groma's own
// internal/discovery.Scanner (plain TCP-connect) is the zero-dependency
// fallback used when naabu isn't installed; this package is the optional
// external tool for SYN-speed scans across large port ranges.
//
// Service/version identification is NOT re-wrapped as a separate nmap
// call: naabu ships its own nmap-service-probes-compatible fingerprint
// engine (`-sV`), which writes product/version/banner into the exact
// same `-json` result line as the port hit. There is no second binary,
// no XML to parse, and no duplicate wrapper — one tool, one schema.
// naabu's `-nmap-cli` flag (full nmap passthrough) remains available to
// a caller via CustomArgs for the rare case a real nmap install is
// wanted instead, but groma does not build or parse for it by default.
//
// Rate (-rate) and concurrency (-c) are naabu's own native flags; no
// masscan or rustscan code is vendored. Two defaults here borrow those
// tools' operating lessons without adopting either as a dependency:
// naabu's own conservative default packet rate (1000 pps, not an
// unbounded flood — the masscan lesson is in the ceiling, not the tool)
// is left untouched unless the caller overrides it, and concurrency
// defaults to a ulimit-aware worker count (internal/sysnet) the way
// RustScan auto-sizes its batch to the host's file-descriptor ceiling.
package naabu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/sysnet"
)

const (
	defaultConcurrency = 25   // naabu's own default (-c)
	maxConcurrency     = 1000 // safety ceiling; never auto-pick above this
)

// Options configures a naabu run. Zero-value Options is a safe,
// conservative default: CONNECT scan (no raw-socket privileges needed),
// naabu's own port/rate defaults, native service-version fingerprinting
// on, CDN edges capped to 80/443.
type Options struct {
	Ports    string // -p, nmap format ("80,443" or "1-1000"). Empty = naabu's own top-100 default.
	TopPorts string // -top-ports ("100"|"1000"|"full"). Ignored if Ports is set.

	ScanType string // -s: "c" (connect, default) or "s" (SYN, needs CAP_NET_RAW/root)

	Rate        int // -rate, packets/sec. 0 = naabu's default (1000).
	Concurrency int // -c, worker threads. 0 = sysnet.RecommendedConcurrency(defaultConcurrency, maxConcurrency).
	Retries     int // -retries. 0 = naabu's default (3).
	TimeoutMS   int // -timeout, per-probe timeout in ms. 0 = naabu's default (1000).

	ExcludeCDN     bool // -exclude-cdn: cap CDN/WAF-fronted hosts to ports 80/443
	ServiceVersion bool // -sV: naabu's native nmap-service-probes fingerprinting

	CustomArgs []string // escape hatch for flags this wrapper doesn't model (e.g. -nmap-cli)
}

// DefaultOptions returns a fast triage baseline: naabu's own top-100
// ports (Ports/TopPorts left empty), CDN-capped, service fingerprinting
// on. This is NOT full coverage — use FullRangeOptions when the goal is
// "never miss a port" (groma's default scan mode; see cmd/groma/cmd).
func DefaultOptions() Options {
	return Options{
		ScanType:       "c",
		ExcludeCDN:     true,
		ServiceVersion: true,
	}
}

// FullRangeOptions returns the exhaustive baseline: every TCP port,
// 1-65535, with every naabu skip mechanism turned off. Verified against
// naabu's own source (not assumed) that three defaults silently reduce
// coverage otherwise:
//   - Ports/TopPorts empty -> naabu's own "-top-ports 100" default
//     (confirmed in naabu's -top-ports help text) — fixed by setting
//     Ports explicitly.
//   - ExcludeCDN -> caps a CDN/WAF-fronted host to ports 80/443 only
//     (pkg/runner: ExcludeCdn) — turned off; a CDN can front more than
//     the web ports, and this mode's whole point is not guessing.
//   - PortThreshold (-pts) / SmartScan (-ss) are both off by default in
//     naabu itself (PortThreshold==0 disables its skip-on-threshold
//     logic; SmartScan requires an explicit -ss) — Options never sets
//     either, so there is nothing to disable, just nothing to confirm.
//
// Speed comes from naabu's own concurrency lever (internal/sysnet, see
// concurrency_unix.go) for the default no-privilege CONNECT scan — rate
// (-rate) matters far less for CONNECT than for SYN, and naabu already
// auto-adjusts Rate/Retries between SYN and CONNECT scan types
// internally (pkg/runner/validate.go), so this wrapper does not
// second-guess that. For a SYN scan (needs CAP_NET_RAW/root), set
// ScanType="s" explicitly and tune Rate for the network — the wrapper
// never escalates privilege or switches scan type on its own.
func FullRangeOptions() Options {
	return Options{
		Ports:          "1-65535",
		ScanType:       "c",
		ExcludeCDN:     false,
		ServiceVersion: true,
	}
}

// Result is one open port naabu reported, with any service data its
// fingerprint engine (or an operator-supplied -nmap-cli) attached.
type Result struct {
	Host      string
	IP        string
	Port      int
	Protocol  string
	IsCDN     bool
	CDNName   string
	Service   string // fingerprinted service name, e.g. "ftp"
	Product   string // e.g. "vsftpd"
	Version   string
	ExtraInfo string
	Banner    string
	CPEs      []string // Common Platform Enumeration ids — the clean version-match key for CVE lookups
}

// jsonLine mirrors naabu's own `-json` output schema exactly (naabu
// v2 pkg/runner/output.go jsonResult) — field names are load-bearing,
// not guessed.
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

// Naabu wraps the upstream `naabu` binary.
type Naabu struct {
	binaryPath string
}

// New locates the naabu binary on $PATH. Safe to construct even when
// the binary is absent — IsAvailable reports false and Scan returns an
// error rather than panicking, so callers can fall back to groma's
// native discovery.Scanner.
func New() *Naabu {
	n := &Naabu{}
	if path, err := exec.LookPath("naabu"); err == nil {
		n.binaryPath = path
	}
	return n
}

// Name returns the tool name.
func (n *Naabu) Name() string { return "naabu" }

// IsAvailable reports whether the binary was located.
func (n *Naabu) IsAvailable() bool { return n.binaryPath != "" }

// BuildArgs renders the naabu command-line arguments for a scan.
// Public so tests can assert the arg shape without invoking the binary.
func BuildArgs(host string, opts Options) []string {
	args := []string{"-host", host, "-json", "-silent", "-duc"}

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
	if opts.ExcludeCDN {
		args = append(args, "-exclude-cdn")
	}
	if opts.ServiceVersion {
		args = append(args, "-sV")
	}
	args = append(args, opts.CustomArgs...)
	return args
}

// Scan runs naabu against host and parses its JSON-lines output into
// Results. A non-nil error means the run didn't complete cleanly — but
// the Results returned alongside it are whatever naabu had already
// printed before that happened, not discarded. This matters most for a
// context timeout: exec.CommandContext kills naabu mid-scan, and the
// ports it had already reported before the kill are real findings, not
// noise to throw away. Callers should treat a non-nil error here as
// "coverage may be incomplete" and surface that, not as "nothing was
// found" — those are different facts.
func (n *Naabu) Scan(ctx context.Context, host string, opts Options) ([]Result, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("naabu binary not found on $PATH")
	}
	cmd := exec.CommandContext(ctx, n.binaryPath, BuildArgs(host, opts)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	results := ParseJSONLines(stdout.String())
	if runErr != nil {
		if ctx.Err() != nil {
			return results, fmt.Errorf("naabu scan incomplete (%d result(s) captured before it stopped): %w",
				len(results), ctx.Err())
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return results, fmt.Errorf("naabu exited with code %d: %s",
				exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return results, fmt.Errorf("naabu run error: %w", runErr)
	}
	return results, nil
}

// ParseJSONLines converts naabu's `-json` stdout into Results.
// Malformed lines are skipped, not fatal — naabu occasionally interleaves
// a banner or warning even with -silent.
func ParseJSONLines(raw string) []Result {
	var out []Result
	if raw == "" {
		return out
	}
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
		out = append(out, Result{
			Host:      jl.Host,
			IP:        jl.IP,
			Port:      jl.Port,
			Protocol:  jl.Protocol,
			IsCDN:     jl.IsCDNIP,
			CDNName:   jl.CDNName,
			Service:   jl.Name,
			Product:   jl.Product,
			Version:   jl.Version,
			ExtraInfo: jl.ExtraInfo,
			Banner:    jl.Banner,
			CPEs:      jl.CPEs,
		})
	}
	return out
}

// ToFinding renders a Result with identified service data as a
// core.Finding — informational only (service-ID is recon, not a
// vulnerability on its own); groma's detection packages decide what,
// if anything, that service exposure means.
func (r Result) ToFinding(host string) *core.Finding {
	f := core.NewFinding("open_port", core.SeverityInfo)
	f.Tool = "naabu"
	f.Host, f.Port, f.Protocol = host, r.Port, r.Protocol
	f.Service = r.Service
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
