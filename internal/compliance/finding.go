package compliance

import (
	"fmt"

	"github.com/TyrusRC/groma/internal/core"
)

// ToFindings renders every FAILED/WARNING result as a core.Finding.
// PASSED results produce no finding (a passing control is not a
// vulnerability, matching the project's "no INFO tier" severity model).
// UNSUPPORTED/ERROR results produce no finding either — they are a
// coverage gap, not evidence of a problem — but are returned separately
// so the caller can report them honestly instead of silently dropping
// them (see cmd/groma/cmd/scan.go).
func ToFindings(host string, results []Result) (findings core.Findings, unsupported, errored []Result) {
	for _, r := range results {
		switch r.Status {
		case StatusFailed, StatusWarning:
			sev := core.SeverityMedium
			if r.Status == StatusWarning {
				sev = core.SeverityLow
			}
			f := core.NewFinding("compliance-"+shortHash(r.Item.Description), sev)
			f.Tool = "groma"
			f.Host = host
			f.Protocol = "local"
			f.Title = r.Item.Description
			f.Description = r.Item.Info
			f.Remediation = r.Item.Solution
			if r.Item.Reference != "" {
				f.References = []string{r.Item.Reference}
			}
			f.Evidence = fmt.Sprintf("compliance check %q (%s): %s", r.Item.Description, r.Item.Type, truncate(r.Output, 500))
			findings = append(findings, f)
		case StatusUnsupported, StatusError:
			if r.Status == StatusUnsupported {
				unsupported = append(unsupported, r)
			} else {
				errored = append(errored, r)
			}
		}
	}
	return findings, unsupported, errored
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// shortHash gives each compliance finding a stable, short, non-sensitive
// id derived from its description — good enough for dedup without
// pulling in a hashing dependency beyond stdlib.
func shortHash(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
