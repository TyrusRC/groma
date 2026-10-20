package naabu

import (
	"strings"
	"testing"
)

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBuildArgsDefaults(t *testing.T) {
	args := BuildArgs("10.0.0.5", DefaultOptions())
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-host 10.0.0.5") {
		t.Errorf("expected -host 10.0.0.5, got %q", joined)
	}
	if !hasFlag(args, "-exclude-cdn") {
		t.Errorf("DefaultOptions sets ExcludeCDN=true, expected -exclude-cdn in %q", joined)
	}
	// NOTE: -sV is intentionally NOT passed — it's broken in naabu 2.6.1.
	// Service fingerprinting is done by groma's native probe engine.
	if hasFlag(args, "-sV") {
		t.Errorf("-sV should not be passed (broken in naabu 2.6.1), got %q", joined)
	}
	if !strings.Contains(joined, "-s c") {
		t.Errorf("expected default scan type 'c' (connect, no privileges needed), got %q", joined)
	}
	if hasFlag(args, "-rate") {
		t.Errorf("Rate=0 should omit -rate and use naabu's own default, got %q", joined)
	}
	if !hasFlag(args, "-c") {
		t.Errorf("concurrency should always be set explicitly (ulimit-aware default), got %q", joined)
	}
}

func TestBuildArgsCustomOverridesDefaults(t *testing.T) {
	args := BuildArgs("target.example", Options{
		Ports:       "1-1000",
		Rate:        2000,
		Concurrency: 50,
		ScanType:    "s",
	})
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-p 1-1000") {
		t.Errorf("expected explicit -p 1-1000, got %q", joined)
	}
	if !strings.Contains(joined, "-rate 2000") {
		t.Errorf("expected explicit -rate 2000, got %q", joined)
	}
	if !strings.Contains(joined, "-c 50") {
		t.Errorf("expected explicit -c 50 (no ulimit override when caller sets Concurrency), got %q", joined)
	}
	if !strings.Contains(joined, "-s s") {
		t.Errorf("expected explicit SYN scan type, got %q", joined)
	}
	if hasFlag(args, "-exclude-cdn") || hasFlag(args, "-sV") {
		t.Errorf("zero-value Options should not set flags the caller didn't ask for, got %q", joined)
	}
}

func TestFullRangeOptionsCoversEveryPortAndSkipsNoHost(t *testing.T) {
	args := BuildArgs("10.0.0.5", FullRangeOptions())
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-p 1-65535") {
		t.Fatalf("FullRangeOptions must scan the entire TCP range, got %q", joined)
	}
	if hasFlag(args, "-exclude-cdn") {
		t.Errorf("FullRangeOptions must not cap CDN-fronted hosts to 80/443, got %q", joined)
	}
	if hasFlag(args, "-top-ports") {
		t.Errorf("FullRangeOptions must never fall back to naabu's top-ports default, got %q", joined)
	}
	if hasFlag(args, "-pts") || hasFlag(args, "-port-threshold") {
		t.Errorf("FullRangeOptions must never enable naabu's skip-on-threshold behavior, got %q", joined)
	}
	if hasFlag(args, "-ss") || hasFlag(args, "-smart-scan") {
		t.Errorf("FullRangeOptions must never enable predictive (non-exhaustive) scanning, got %q", joined)
	}
}

func TestDefaultOptionsDoesNotClaimFullRange(t *testing.T) {
	args := BuildArgs("10.0.0.5", DefaultOptions())
	if hasFlag(args, "-p") {
		t.Errorf("DefaultOptions is the fast-triage baseline; it must not pass -p, or callers relying on FullRangeOptions for full coverage would be silently narrowed if this changed, got %q", strings.Join(args, " "))
	}
}

func TestBuildArgsTopPortsIgnoredWhenPortsSet(t *testing.T) {
	args := BuildArgs("h", Options{Ports: "80,443", TopPorts: "1000"})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-p 80,443") {
		t.Errorf("expected -p 80,443, got %q", joined)
	}
	if hasFlag(args, "-top-ports") {
		t.Errorf("TopPorts must be ignored once Ports is set (naabu treats them as alternatives), got %q", joined)
	}
}

func TestBuildArgsNewFlags(t *testing.T) {
	args := BuildArgs("h", Options{
		WarmUpTimeS:         5,
		DisplayCDN:          true,
		ServiceDiscovery:    true,
		Verify:              true,
		Passive:             true,
		SmartScan:           true,
		PredictionThreshold: 60,
		ExcludeHosts:        "10.0.0.1,10.0.0.2",
		ExcludePorts:        "25,587",
		PortThreshold:       100,
	})
	joined := strings.Join(args, " ")
	// NOTE: -sD and -sV are intentionally NOT passed (broken in naabu 2.6.1).
	for _, want := range []string{
		"-warm-up-time 5", "-display-cdn", "-verify", "-passive",
		"-ss", "-pt 60", "-exclude-hosts 10.0.0.1,10.0.0.2",
		"-exclude-ports 25,587", "-port-threshold 100",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in args, got %q", want, joined)
		}
	}
}

func TestBuildArgsSmartScanOmitsThresholdWhenUnset(t *testing.T) {
	args := BuildArgs("h", Options{SmartScan: true})
	if hasFlag(args, "-pt") {
		t.Errorf("PredictionThreshold=0 should omit -pt and use naabu's own default, got %q", strings.Join(args, " "))
	}
}

func TestParseJSONLines(t *testing.T) {
	raw := `{"host":"scanme.example","ip":"10.0.0.5","port":21,"protocol":"tcp","cdn":false,"name":"ftp","product":"vsftpd","version":"3.0.3","banner":"220 (vsFTPd 3.0.3)","cpes":["cpe:/a:vsftpd_project:vsftpd:3.0.3"]}
not json, a stray banner line naabu printed despite -silent
{"host":"scanme.example","ip":"10.0.0.5","port":443,"protocol":"tcp","cdn":true,"cdn-name":"cloudflare"}
`
	results := ParseJSONLines(raw)
	if len(results) != 2 {
		t.Fatalf("expected 2 parsed results (malformed line skipped), got %d: %+v", len(results), results)
	}

	ftp := results[0]
	if ftp.Port != 21 || ftp.Service != "ftp" || ftp.Product != "vsftpd" || ftp.Version != "3.0.3" {
		t.Errorf("ftp result mismapped from naabu's jsonLine schema: %+v", ftp)
	}
	if ftp.Banner != "220 (vsFTPd 3.0.3)" {
		t.Errorf("expected banner to round-trip, got %q", ftp.Banner)
	}
	if len(ftp.CPEs) != 1 || ftp.CPEs[0] != "cpe:/a:vsftpd_project:vsftpd:3.0.3" {
		t.Errorf("expected CPE to round-trip (it's the match key for CVE lookups), got %+v", ftp.CPEs)
	}

	cdn := results[1]
	if !cdn.IsCDN || cdn.CDNName != "cloudflare" {
		t.Errorf("expected CDN fields to map from 'cdn'/'cdn-name', got %+v", cdn)
	}
}

func TestParseJSONLinesEmpty(t *testing.T) {
	if got := ParseJSONLines(""); got != nil {
		t.Errorf("expected nil for empty input, got %+v", got)
	}
}

func TestDefaultConcurrencyIsUsedWhenUnset(t *testing.T) {
	args := BuildArgs("h", Options{})
	if !hasFlag(args, "-c") {
		t.Fatalf("expected -c to always be set, got %q", strings.Join(args, " "))
	}
	// sysnet.RecommendedConcurrency is exercised directly in internal/sysnet's
	// own tests; here we only check BuildArgs always renders some concurrency.
}

func TestToFindingIsInformational(t *testing.T) {
	r := Result{Port: 21, Protocol: "tcp", Service: "ftp", Product: "vsftpd", Version: "3.0.3", Banner: "220 ready"}
	f := r.ToFinding("10.0.0.5")
	if f.Severity != "info" {
		t.Errorf("a raw port/service identification is recon, not a vulnerability — expected info severity, got %s", f.Severity)
	}
	if f.Host != "10.0.0.5" || f.Port != 21 || f.Service != "ftp" {
		t.Errorf("finding location fields mismapped: %+v", f)
	}
	if f.Product != "vsftpd" || f.Version != "3.0.3" {
		t.Errorf("expected Product/Version to be exposed as structured fields, not just folded into Title, got %+v", f)
	}
	if f.Evidence != "Banner: 220 ready" {
		t.Errorf("expected evidence to carry the banner, got %q", f.Evidence)
	}
}
