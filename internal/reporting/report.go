// Package reporting renders a completed scan as JSON, human-readable
// text, or SARIF (for CI code-scanning integration).
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
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

// WriteText writes the report as human-readable text.
func (r *Report) WriteText(w io.Writer) error {
	fmt.Fprintln(w, "====================================================================")
	fmt.Fprintln(w, "                        groma SCAN REPORT                          ")
	fmt.Fprintln(w, "====================================================================")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Report Version: %s\n", r.Version)
	fmt.Fprintf(w, "Generated At:   %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Scan Duration:  %dms\n", r.DurationMS)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "TARGETS:")
	for _, t := range r.Targets {
		fmt.Fprintf(w, "  - %s\n", t)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "SUMMARY:")
	fmt.Fprintf(w, "  Total Findings: %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(w, "  Critical: %d\n", r.Summary.Critical)
	fmt.Fprintf(w, "  High:     %d\n", r.Summary.High)
	fmt.Fprintf(w, "  Medium:   %d\n", r.Summary.Medium)
	fmt.Fprintf(w, "  Low:      %d\n", r.Summary.Low)
	fmt.Fprintf(w, "  Info:     %d\n", r.Summary.Info)
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}

	fmt.Fprintln(w, "FINDINGS:")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%s] %s\n", severityLabel(f.Severity), f.Title)
		fmt.Fprintf(w, "  Host:     %s:%d/%s\n", f.Host, f.Port, f.Protocol)
		if f.Service != "" {
			fmt.Fprintf(w, "  Service:  %s\n", f.Service)
		}
		if f.Description != "" {
			fmt.Fprintf(w, "  Detail:   %s\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "  Evidence: %s\n", f.Evidence)
		}
		if len(f.CWE) > 0 {
			fmt.Fprintf(w, "  CWE:      %v\n", f.CWE)
		}
		if f.CVSS > 0 {
			fmt.Fprintf(w, "  CVSS:     %.1f\n", f.CVSS)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  Fix:      %s\n", f.Remediation)
		}
	}
	return nil
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
