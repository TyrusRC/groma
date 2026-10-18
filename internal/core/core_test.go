package core

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical,
		"HIGH":     SeverityHigh,
		" medium ": SeverityMedium,
		"low":      SeverityLow,
		"info":     SeverityInfo,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("expected an error for an invalid severity string")
	}
}

func TestFilterByMinSeverity(t *testing.T) {
	findings := Findings{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
	}
	got := findings.FilterByMinSeverity(SeverityHigh)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings at or above high, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity != SeverityCritical && f.Severity != SeverityHigh {
			t.Errorf("filtered result included a below-threshold severity: %s", f.Severity)
		}
	}
}

func TestSortBySeverityWorstFirst(t *testing.T) {
	findings := Findings{
		{Severity: SeverityLow},
		{Severity: SeverityCritical},
		{Severity: SeverityMedium},
	}
	findings.SortBySeverity()
	if findings[0].Severity != SeverityCritical || findings[len(findings)-1].Severity != SeverityLow {
		order := make([]string, len(findings))
		for i, f := range findings {
			order[i] = string(f.Severity)
		}
		t.Errorf("expected worst-first order, got %v", order)
	}
}
