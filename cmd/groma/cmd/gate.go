package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
)

// gateExitCode is returned when --fail-on is triggered, kept distinct
// from 1 (operational error) so CI can tell a vulnerable-but-healthy
// scan apart from a crashed one.
const gateExitCode = 2

// gateError signals that findings met or exceeded the --fail-on threshold.
type gateError struct {
	Threshold core.Severity
	Count     int
}

func (e *gateError) Error() string {
	return fmt.Sprintf("fail-on: %d finding(s) at or above severity %q", e.Count, e.Threshold)
}

// ExitCode maps a command error to a process exit code: 0 for success,
// gateExitCode when a --fail-on threshold was met, 1 for any other error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ge *gateError
	if errors.As(err, &ge) {
		return gateExitCode
	}
	return 1
}

// evaluateGate reports whether findings should fail the run given the
// --fail-on threshold. An empty value or "none" disables gating.
//
// Unless includeUnproven is set, findings triaged "unproven" (version-
// based matches on distro-packaged hosts, which the distro may have
// already backport-patched) do NOT trip the gate: a CI gate should fail
// on confirmed issues, not on leads that still need --ssh-audit to prove.
func evaluateGate(findings core.Findings, failOn string, includeUnproven bool) (fail bool, count int, err error) {
	v := strings.ToLower(strings.TrimSpace(failOn))
	if v == "" || v == "none" {
		return false, 0, nil
	}
	threshold, err := core.ParseSeverity(v)
	if err != nil {
		return false, 0, fmt.Errorf("invalid --fail-on value: %w", err)
	}
	for _, f := range findings.FilterByMinSeverity(threshold) {
		if !includeUnproven && f.VersionUnconfirmed {
			continue
		}
		count++
	}
	return count > 0, count, nil
}
