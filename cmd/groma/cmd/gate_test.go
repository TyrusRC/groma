package cmd

import (
	"testing"

	"github.com/TyrusRC/groma/internal/core"
)

func critFinding(triage string) *core.Finding {
	f := core.NewFinding("CVE-2024-0001", core.SeverityCritical)
	f.Host = "10.0.0.5"
	f.Triage = triage
	return f
}

func TestEvaluateGateExcludesUnprovenByDefault(t *testing.T) {
	findings := core.Findings{critFinding("unproven")}

	fail, count, err := evaluateGate(findings, "high", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fail || count != 0 {
		t.Errorf("an unproven critical must not trip the gate by default, got fail=%v count=%d", fail, count)
	}

	// With the opt-in flag it counts.
	fail, count, _ = evaluateGate(findings, "high", true)
	if !fail || count != 1 {
		t.Errorf("--fail-on-unproven should count the unproven critical, got fail=%v count=%d", fail, count)
	}
}

func TestEvaluateGateTripsOnConfirmedFinding(t *testing.T) {
	findings := core.Findings{critFinding("")} // not triaged unproven
	fail, count, err := evaluateGate(findings, "high", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fail || count != 1 {
		t.Errorf("a confirmed critical must trip the gate, got fail=%v count=%d", fail, count)
	}
}

func TestEvaluateGateDisabledWhenEmpty(t *testing.T) {
	if fail, _, _ := evaluateGate(core.Findings{critFinding("")}, "", false); fail {
		t.Errorf("empty --fail-on must disable the gate")
	}
}
