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

func TestFindingsDedupCollapsesSameCVEAtSameLocation(t *testing.T) {
	bundled := NewFinding("CVE-2023-38408", SeverityCritical)
	bundled.Host, bundled.Port, bundled.Protocol = "10.0.0.5", 22, "tcp"
	bundled.Remediation = "Upgrade OpenSSH."

	// Same CVE from NVD, carries CVSS the bundled one lacks.
	fromNVD := NewFinding("CVE-2023-38408", SeverityCritical)
	fromNVD.Host, fromNVD.Port, fromNVD.Protocol = "10.0.0.5", 22, "tcp"
	fromNVD.CVSS = 9.8

	// A different CVE at the same location must survive.
	other := NewFinding("CVE-2024-6387", SeverityCritical)
	other.Host, other.Port, other.Protocol = "10.0.0.5", 22, "tcp"

	out := Findings{bundled, fromNVD, other}.Dedup()
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d", len(out))
	}
	if out[0].CVSS != 9.8 {
		t.Errorf("merge should fill missing CVSS from the duplicate, got %v", out[0].CVSS)
	}
	if out[0].Remediation == "" {
		t.Errorf("merge should keep the first finding's remediation")
	}
}

func TestFindingsDedupKeepsDistinctTypesAndHosts(t *testing.T) {
	a := NewFinding("open_port", SeverityInfo)
	a.Host, a.Port, a.Protocol = "10.0.0.5", 22, "tcp"
	b := NewFinding("CVE-2024-6387", SeverityCritical)
	b.Host, b.Port, b.Protocol = "10.0.0.5", 22, "tcp"
	c := NewFinding("open_port", SeverityInfo)
	c.Host, c.Port, c.Protocol = "10.0.0.6", 22, "tcp"
	if out := (Findings{a, b, c}).Dedup(); len(out) != 3 {
		t.Errorf("distinct (host,port,type) findings must not be merged, got %d", len(out))
	}
}
