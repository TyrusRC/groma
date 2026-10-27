package cmd

import (
	"reflect"
	"testing"
	"time"

	"github.com/TyrusRC/groma/internal/tools/naabu"
)

func TestNaabuOptionsForSynRetriesExceedConnect(t *testing.T) {
	old := scanScanType
	defer func() { scanScanType = old }()

	scanScanType = "syn"
	syn := naabuOptionsFor()
	scanScanType = "connect"
	conn := naabuOptionsFor()

	if syn.ScanType != "s" {
		t.Fatalf("syn ScanType=%q, want s", syn.ScanType)
	}
	if syn.Retries != naabu.SynRetries {
		t.Errorf("syn retries=%d, want %d", syn.Retries, naabu.SynRetries)
	}
	if syn.Retries <= conn.Retries {
		t.Errorf("SYN retries (%d) must exceed connect retries (%d): a dropped SYN-ACK on a defended host is lost without extra retransmits", syn.Retries, conn.Retries)
	}
}

func TestCanonHostMatchesEquivalentAddressForms(t *testing.T) {
	// The bug this guards: a target expands to netip's canonical IPv6 text,
	// but a scanner may echo the same address bracketed, upper-cased or
	// zero-expanded. If those don't canonicalise equal, the result is
	// bucketed under a key the analysis loop never reads and silently lost.
	pairs := [][2]string{
		{"2001:db8::1", "[2001:db8::1]"},
		{"2001:db8::1", "2001:DB8::1"},
		{"2001:db8::1", "2001:db8:0:0:0:0:0:1"},
		{"192.168.0.1", "192.168.0.1"},
	}
	for _, p := range pairs {
		if canonHost(p[0]) != canonHost(p[1]) {
			t.Errorf("canonHost(%q)=%q should equal canonHost(%q)=%q",
				p[0], canonHost(p[0]), p[1], canonHost(p[1]))
		}
	}
	// A hostname is not an IP literal and must pass through unchanged, not
	// collapse into some other host's bucket.
	if canonHost("scanme.nmap.org") != "scanme.nmap.org" {
		t.Errorf("hostname should pass through unchanged, got %q", canonHost("scanme.nmap.org"))
	}
	if canonHost("a.example") == canonHost("b.example") {
		t.Errorf("distinct hostnames must not share a key")
	}
}

func TestConnectTimeoutForRTT(t *testing.T) {
	cases := []struct {
		name string
		rtt  time.Duration
		want int
	}{
		{"no answer -> conservative", 0, 1500},
		{"localhost-fast -> floor", 300 * time.Microsecond, 1000},
		{"low rtt still floored", 100 * time.Millisecond, 1000},
		{"mid rtt scales 3x", 1 * time.Second, 3000},
		{"slow rtt capped", 2 * time.Second, 4000},
		{"very slow still capped", 10 * time.Second, 4000},
	}
	for _, c := range cases {
		if got := connectTimeoutForRTT(c.rtt); got != c.want {
			t.Errorf("%s: connectTimeoutForRTT(%v)=%d, want %d", c.name, c.rtt, got, c.want)
		}
	}
}

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
