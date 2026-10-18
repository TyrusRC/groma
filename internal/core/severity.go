package core

import (
	"fmt"
	"strings"
)

// Severity mirrors assay's core.Severity exactly, so a groma report and an
// assay report rank and filter the same way in anything that consumes both
// (Praetor's import_scan_results already understands this five-level scale).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) String() string { return string(s) }

func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Rank orders severities worst-first for sorting (critical=0 ... info=4).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

// ParseSeverity parses a string into a Severity value, case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info", "informational":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity: %q", s)
	}
}
