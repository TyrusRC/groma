// Package nmap wraps the nmap binary for service version detection and
// port scanning. This is the second-choice scanner in groma's pipeline:
// naabu is preferred for speed (SYN-rate scanning), but when naabu's
// -sV is unavailable or nmap's deeper probes are needed, this wrapper
// provides full nmap -sV/-sC output parsed into the same Result shape
// naabu uses — so the rest of groma (CVE checks, creds, triage) works
// identically regardless of which scanner found the service.
package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
)

// Options configures an nmap run.
type Options struct {
	Ports       string // -p, nmap format. Empty = nmap's default top 1000.
	ScanType    string // -sT (connect, default) or -sS (SYN, needs root)
	ServiceScan bool   // -sV: version detection
	ScriptScan  bool   // -sC: default scripts
	Timing      int    // -T0 through -T5. 0 = unset (nmap default T3).
	ExtraArgs   []string
}

// DefaultOptions returns a service-version scan with connect probes.
func DefaultOptions() Options {
	return Options{
		ScanType:    "-sT",
		ServiceScan: true,
	}
}

// FullRangeOptions returns a full 1-65535 service version scan.
func FullRangeOptions() Options {
	return Options{
		Ports:       "1-65535",
		ScanType:    "-sT",
		ServiceScan: true,
		Timing:      4,
	}
}

// Result mirrors naabu.Result so the rest of groma treats both scanners
// identically.
type Result struct {
	Host     string
	IP       string
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
	Banner   string
	CPEs     []string
}

// ToFinding renders a Result as an informational core.Finding.
func (r Result) ToFinding(host string) *core.Finding {
	f := core.NewFinding("open_port", core.SeverityInfo)
	f.Tool = "nmap"
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

// Nmap wraps the upstream `nmap` binary.
type Nmap struct {
	binaryPath string
}

// New locates the nmap binary on $PATH.
func New() *Nmap {
	n := &Nmap{}
	if path, err := exec.LookPath("nmap"); err == nil {
		n.binaryPath = path
	}
	return n
}

// IsAvailable reports whether nmap was found.
func (n *Nmap) IsAvailable() bool { return n.binaryPath != "" }

// BuildArgs renders the nmap command-line for a scan.
func BuildArgs(host string, opts Options) []string {
	args := []string{"-Pn", "-oX", "-"} // skip host discovery, XML to stdout

	if opts.ScanType != "" {
		args = append(args, opts.ScanType)
	} else {
		args = append(args, "-sT")
	}
	if opts.Ports != "" {
		args = append(args, "-p", opts.Ports)
	}
	if opts.ServiceScan {
		args = append(args, "-sV")
	}
	if opts.ScriptScan {
		args = append(args, "-sC")
	}
	if opts.Timing > 0 && opts.Timing <= 5 {
		args = append(args, fmt.Sprintf("-T%d", opts.Timing))
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, host)
	return args
}

// Scan runs nmap and parses the XML output into Results.
func (n *Nmap) Scan(ctx context.Context, host string, opts Options) ([]Result, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("nmap binary not found on $PATH")
	}
	cmd := exec.CommandContext(ctx, n.binaryPath, BuildArgs(host, opts)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	results, parseErr := ParseXML(stdout.Bytes(), host)
	if parseErr != nil && runErr != nil {
		return results, fmt.Errorf("nmap: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
	}
	if runErr != nil {
		return results, fmt.Errorf("nmap exited with error: %w", runErr)
	}
	return results, parseErr
}

// --- nmap XML parsing ---

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string    `xml:"name,attr"`
	Product   string    `xml:"product,attr"`
	Version   string    `xml:"version,attr"`
	ExtraInfo string    `xml:"extrainfo,attr"`
	Tunnel    string    `xml:"tunnel,attr"`
	CPEs      []nmapCPE `xml:"cpe"`
}

type nmapCPE struct {
	Value string `xml:",chardata"`
}

// ParseXML converts nmap's -oX output into Results.
func ParseXML(data []byte, defaultHost string) ([]Result, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap: parsing XML: %w", err)
	}

	var out []Result
	for _, h := range run.Hosts {
		ip := defaultHost
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			r := Result{
				Host:     defaultHost,
				IP:       ip,
				Port:     p.PortID,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			}
			if p.Service.ExtraInfo != "" {
				r.Banner = p.Service.ExtraInfo
			}
			for _, cpe := range p.Service.CPEs {
				if cpe.Value != "" {
					r.CPEs = append(r.CPEs, cpe.Value)
				}
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// ObservationsPortSpec returns an nmap -p spec matching the given ports.
func ObservationsPortSpec(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ",")
}
