package core

import (
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Finding represents a discovered network/infrastructure issue. Shaped like
// vigil's core.Finding (same Severity/CWE/CVSS/remediation fields) so a
// consumer that already understands one understands the other, but the
// location fields are network-native (Host/Port/Protocol/Service) instead
// of (URL/Parameter).
type Finding struct {
	ID   string `json:"id"`
	Tool string `json:"tool,omitempty"`

	Type     string   `json:"type"`
	Severity Severity `json:"severity"`

	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`

	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp | udp
	Service  string `json:"service,omitempty"`  // e.g. "ftp", "telnet" (from banner/port)
	Product  string `json:"product,omitempty"`  // e.g. "vsftpd" (naabu -sV fingerprint; empty without it)
	Version  string `json:"version,omitempty"`

	Evidence string `json:"evidence,omitempty"` // what was actually observed, never destructive proof

	// Triage/Confidence are set by internal/haruspex when a Haruspex decision
	// server is reachable; empty/zero means "not triaged" (server absent or
	// errored), never "ruled out" — Haruspex never removes a candidate.
	Triage     string  `json:"triage,omitempty"`     // "confirmed" | "likely_noise" | "unproven" | "" (not triaged)
	Confidence float64 `json:"confidence,omitempty"` // Haruspex P(yes) this is a real, reportable finding

	CWE        []string `json:"cwe,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`

	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}

// NewFinding creates a Finding with a generated ID and the current timestamp.
func NewFinding(findingType string, severity Severity) *Finding {
	return &Finding{
		ID:        uuid.New().String(),
		Type:      findingType,
		Severity:  severity,
		Timestamp: time.Now(),
	}
}

// Validate checks the finding has the fields a report needs to be useful.
func (f *Finding) Validate() error {
	if f.ID == "" {
		return errors.New("finding ID is required")
	}
	if f.Type == "" {
		return errors.New("finding type is required")
	}
	if !f.Severity.IsValid() {
		return errors.New("invalid severity")
	}
	if f.Host == "" {
		return errors.New("finding host is required")
	}
	return nil
}

// Findings is a slice of Finding with report-building helpers.
type Findings []*Finding

// SortBySeverity sorts findings worst-first (critical, then high, ...).
func (f Findings) SortBySeverity() {
	sort.SliceStable(f, func(i, j int) bool {
		return f[i].Severity.Rank() < f[j].Severity.Rank()
	})
}

// FilterByMinSeverity returns findings at or above minSeverity (critical is
// the highest rank, so "at or above" means Rank() <= minSeverity.Rank()).
func (f Findings) FilterByMinSeverity(minSeverity Severity) Findings {
	threshold := minSeverity.Rank()
	result := make(Findings, 0)
	for _, finding := range f {
		if finding.Severity.Rank() <= threshold {
			result = append(result, finding)
		}
	}
	return result
}
