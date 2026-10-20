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
	"os/exec"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/sysnet"
)

const (
	defaultConcurrency = 25
	maxConcurrency     = 1000
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

// DefaultOptions returns a fast triage baseline.
func DefaultOptions() Options {
	return Options{
		ScanType:   "c",
		ExcludeCDN: true,
	}
}

// FullRangeOptions returns exhaustive 1-65535.
func FullRangeOptions() Options {
	return Options{
		Ports:      "1-65535",
		ScanType:   "c",
		ExcludeCDN: false,
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
	n := &Naabu{}
	if path, err := exec.LookPath("naabu"); err == nil {
		n.binaryPath = path
	}
	return n
}

func (n *Naabu) Name() string      { return "naabu" }
func (n *Naabu) IsAvailable() bool { return n.binaryPath != "" }

// BuildArgs renders naabu CLI arguments. NOTE: -sV/-sD are intentionally
// omitted — they're broken in naabu 2.6.1. Service fingerprinting is
// done by groma's native probe engine instead.
func BuildArgs(host string, opts Options) []string {
	args := []string{"-host", host, "-json", "-silent", "-duc", "-Pn"}

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
	if opts.Verify {
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

// Scan runs naabu for port discovery and parses JSON output.
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

// ParseJSONLines converts naabu's -json stdout into Results.
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
			Host: jl.Host, IP: jl.IP, Port: jl.Port, Protocol: jl.Protocol,
			IsCDN: jl.IsCDNIP, CDNName: jl.CDNName, Service: jl.Name,
			Product: jl.Product, Version: jl.Version, ExtraInfo: jl.ExtraInfo,
			Banner: jl.Banner, CPEs: jl.CPEs,
		})
	}
	return out
}
