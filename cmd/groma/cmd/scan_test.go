package cmd

import (
	"reflect"
	"testing"
)

func TestParsePortSpecSingleAndList(t *testing.T) {
	got, err := parsePortSpec("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{80, 443, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePortSpecRange(t *testing.T) {
	got, err := parsePortSpec("20-22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{20, 21, 22}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePortSpecMixed(t *testing.T) {
	got, err := parsePortSpec("22,80-82,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{22, 80, 81, 82, 443}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePortSpecRejectsOutOfRangeAndMalformed(t *testing.T) {
	for _, bad := range []string{"0", "65536", "100-50", "abc", "1-99999"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Errorf("parsePortSpec(%q) expected an error, got none", bad)
		}
	}
}

func TestNativePortListDefaultsToFullRange(t *testing.T) {
	old := scanFast
	oldPorts := scanPorts
	defer func() { scanFast, scanPorts = old, oldPorts }()
	scanFast, scanPorts = false, ""

	ports, err := nativePortList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 65535 || ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Errorf("expected the full 1-65535 range by default, got len=%d first=%d last=%d",
			len(ports), ports[0], ports[len(ports)-1])
	}
}

func TestNativePortListFastModeUsesScannerDefault(t *testing.T) {
	old := scanFast
	oldPorts := scanPorts
	defer func() { scanFast, scanPorts = old, oldPorts }()
	scanFast, scanPorts = true, ""

	ports, err := nativePortList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ports != nil {
		t.Errorf("expected nil (let discovery.Scanner use its own DefaultPorts), got %v", ports)
	}
}

func TestNaabuOptionsForDefaultsToFullRange(t *testing.T) {
	old := scanFast
	oldPorts, oldRate, oldConcurrency := scanPorts, scanRate, scanConcurrency
	defer func() {
		scanFast, scanPorts, scanRate, scanConcurrency = old, oldPorts, oldRate, oldConcurrency
	}()
	scanFast, scanPorts, scanRate, scanConcurrency = false, "", 0, 0

	opts := naabuOptionsFor()
	if opts.Ports != "1-65535" {
		t.Errorf("expected the full range by default, got Ports=%q", opts.Ports)
	}
}

func TestNaabuOptionsForExplicitPortsOverridesFastMode(t *testing.T) {
	old := scanFast
	oldPorts := scanPorts
	defer func() { scanFast, scanPorts = old, oldPorts }()
	scanFast, scanPorts = true, "80,443"

	opts := naabuOptionsFor()
	if opts.Ports != "80,443" {
		t.Errorf("expected explicit --ports to win over --fast, got Ports=%q", opts.Ports)
	}
}

func TestNaabuOptionsForPassesThroughRateAndConcurrency(t *testing.T) {
	oldRate, oldConcurrency := scanRate, scanConcurrency
	defer func() { scanRate, scanConcurrency = oldRate, oldConcurrency }()
	scanRate, scanConcurrency = 5000, 200

	opts := naabuOptionsFor()
	if opts.Rate != 5000 || opts.Concurrency != 200 {
		t.Errorf("expected explicit rate/concurrency to pass through, got %+v", opts)
	}
}
