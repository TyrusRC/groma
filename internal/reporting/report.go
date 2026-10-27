// Package reporting renders a completed scan as JSON, human-readable
// text, or SARIF (for CI code-scanning integration).
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TyrusRC/groma/internal/core"
)

const (
	reportVersion = "1.0.0"
	toolName      = "groma"
)

// Summary is the per-severity finding count.
type Summary struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

// Report is the top-level scan result.
type Report struct {
	Version     string        `json:"version"`
	Tool        string        `json:"tool"`
	GeneratedAt time.Time     `json:"generated_at"`
	Targets     []string      `json:"targets"`
	DurationMS  int64         `json:"duration_ms"`
	Findings    core.Findings `json:"findings"`
	Summary     Summary       `json:"summary"`

	// Color enables ANSI color in WriteText. The caller sets it only when
	// the destination is an interactive terminal (never a file or a pipe),
	// so colour codes never leak into redirected output. Not serialized.
	Color bool `json:"-"`
}

// NewReport builds a Report from a scan's findings, sorted worst-first.
func NewReport(targets []string, findings core.Findings, duration time.Duration) *Report {
	findings.SortBySeverity()
	return &Report{
		Version:     reportVersion,
		Tool:        toolName,
		GeneratedAt: time.Now(),
		Targets:     targets,
		DurationMS:  duration.Milliseconds(),
		Findings:    findings,
		Summary:     summarize(findings),
	}
}

func summarize(findings core.Findings) Summary {
	s := Summary{TotalFindings: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case core.SeverityCritical:
			s.Critical++
		case core.SeverityHigh:
			s.High++
		case core.SeverityMedium:
			s.Medium++
		case core.SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the report as human-readable text, grouped by host.
// Hosts are ordered worst-severity-first so the host that needs attention
// is at the top; within each host the open ports are collapsed onto one
// line and only real findings (anything that isn't a bare open port) are
// expanded, so a genuine critical is never buried under port-open noise.
func (r *Report) WriteText(w io.Writer) error {
	c := palette(r.Color)

	fmt.Fprintf(w, "%sgroma scan%s · %d target(s) · %s · %s\n",
		c.bold, c.reset, len(r.Targets), formatDuration(r.DurationMS), r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintln(w, r.summaryLine(c))

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo findings.")
		return nil
	}

	for _, g := range r.groupByHost() {
		fmt.Fprintf(w, "\n%s%s%s", c.bold, g.host, c.reset)
		if len(g.openPorts) > 0 {
			fmt.Fprintf(w, "  %s%s%s", c.dim, openPortsLine(g.openPorts), c.reset)
		}
		fmt.Fprintln(w)

		for _, f := range g.findings {
			loc := ""
			if f.Protocol == "local" {
				loc = " (credentialed)"
			} else if f.Port > 0 {
				loc = fmt.Sprintf(" (%d/%s)", f.Port, f.Protocol)
			}
			label := severityLabel(f.Severity)
			fmt.Fprintf(w, "  %s[%s]%s %s%s\n", c.sev(f.Severity), label, c.reset, f.Title, loc)
			if f.Product != "" {
				fmt.Fprintf(w, "      %s %s\n", f.Product, f.Version)
			}
			if f.Description != "" {
				fmt.Fprintf(w, "      %s\n", f.Description)
			}
			if f.Evidence != "" {
				fmt.Fprintf(w, "      evidence: %s\n", f.Evidence)
			}
			meta := []string{}
			if f.VersionUnconfirmed {
				meta = append(meta, "unconfirmed (version-based)")
			}
			if len(f.CWE) > 0 {
				meta = append(meta, strings.Join(f.CWE, ", "))
			}
			if f.CVSS > 0 {
				meta = append(meta, fmt.Sprintf("CVSS %.1f", f.CVSS))
			}
			if f.Triage != "" {
				meta = append(meta, fmt.Sprintf("triage %s %.2f", f.Triage, f.Confidence))
			}
			if len(meta) > 0 {
				fmt.Fprintf(w, "      %s\n", strings.Join(meta, "  ·  "))
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "      fix: %s\n", f.Remediation)
			}
		}
	}
	return nil
}

// hostGroup collects one host's findings, splitting bare open-port
// observations from real findings.
type hostGroup struct {
	host      string
	worst     int
	openPorts []*core.Finding
	findings  []*core.Finding
}

// groupByHost buckets findings by host and orders the hosts worst-first
// (ties broken by host string for stable output). r.Findings is already
// severity-sorted by NewReport, so each bucket stays severity-ordered.
func (r *Report) groupByHost() []*hostGroup {
	groups := map[string]*hostGroup{}
	var order []*hostGroup
	for _, f := range r.Findings {
		g := groups[f.Host]
		if g == nil {
			g = &hostGroup{host: f.Host, worst: f.Severity.Rank()}
			groups[f.Host] = g
			order = append(order, g)
		}
		if f.Severity.Rank() < g.worst {
			g.worst = f.Severity.Rank()
		}
		if f.Type == "open_port" {
			g.openPorts = append(g.openPorts, f)
		} else {
			g.findings = append(g.findings, f)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].worst != order[j].worst {
			return order[i].worst < order[j].worst
		}
		return order[i].host < order[j].host
	})
	return order
}

// summaryLine renders the per-severity counts on one colored line,
// omitting the zero buckets so the important ones stand out.
func (r *Report) summaryLine(c colors) string {
	parts := []string{}
	add := func(n int, label string, col string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", col, n, label, c.reset))
		}
	}
	add(r.Summary.Critical, "critical", c.critical)
	add(r.Summary.High, "high", c.high)
	add(r.Summary.Medium, "medium", c.medium)
	add(r.Summary.Low, "low", c.low)
	add(r.Summary.Info, "info", c.dim)
	if len(parts) == 0 {
		return "  no findings"
	}
	return "  " + strings.Join(parts, "   ")
}

// openPortsLine renders a host's open ports compactly on one line.
func openPortsLine(ports []*core.Finding) string {
	sort.SliceStable(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	items := make([]string, 0, len(ports))
	for _, f := range ports {
		s := fmt.Sprintf("%d/%s", f.Port, f.Protocol)
		switch {
		case f.Product != "":
			s += " " + strings.TrimSpace(f.Product+" "+f.Version)
		case f.Service != "":
			s += " " + f.Service
		}
		items = append(items, s)
	}
	return fmt.Sprintf("%d open: %s", len(ports), strings.Join(items, ", "))
}

func formatDuration(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).Round(time.Millisecond).String()
}

func severityLabel(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "CRITICAL"
	case core.SeverityHigh:
		return "HIGH"
	case core.SeverityMedium:
		return "MEDIUM"
	case core.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// colors holds the ANSI escape codes WriteText uses. When color is
// disabled every field is the empty string, so the same rendering code
// produces clean plain text — no escape codes leak into a file or pipe.
type colors struct {
	bold, dim, reset                        string
	critical, high, medium, low, info       string
}

func (c colors) sev(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return c.critical
	case core.SeverityHigh:
		return c.high
	case core.SeverityMedium:
		return c.medium
	case core.SeverityLow:
		return c.low
	default:
		return c.dim
	}
}

func palette(enabled bool) colors {
	if !enabled {
		return colors{}
	}
	return colors{
		bold:     "\x1b[1m",
		dim:      "\x1b[90m",
		reset:    "\x1b[0m",
		critical: "\x1b[1;91m", // bold red
		high:     "\x1b[91m",   // red
		medium:   "\x1b[93m",   // yellow
		low:      "\x1b[94m",   // blue
		info:     "\x1b[90m",   // grey
	}
}
