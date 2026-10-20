package nmap

import (
	"testing"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sT -sV -p22,80 scanme.nmap.org -oX -">
<host>
<address addr="45.33.32.156" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu 2ubuntu2.13" tunnel="" method="probed">
<cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>
<cpe>cpe:/o:canonical:ubuntu_linux</cpe>
</service>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)" tunnel="" method="probed">
<cpe>cpe:/a:apache:http_server:2.4.7</cpe>
</service>
</port>
<port protocol="tcp" portid="443">
<state state="closed"/>
<service name="https"/>
</port>
</ports>
</host>
</nmaprun>`

func TestParseXML(t *testing.T) {
	results, err := ParseXML([]byte(sampleXML), "scanme.nmap.org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (open ports only), got %d", len(results))
	}

	ssh := results[0]
	if ssh.Port != 22 || ssh.Service != "ssh" {
		t.Errorf("port 22: expected ssh, got port=%d svc=%s", ssh.Port, ssh.Service)
	}
	if ssh.Product != "OpenSSH" || ssh.Version != "6.6.1p1" {
		t.Errorf("port 22: expected OpenSSH 6.6.1p1, got %s %s", ssh.Product, ssh.Version)
	}
	if len(ssh.CPEs) != 2 {
		t.Errorf("port 22: expected 2 CPEs, got %d", len(ssh.CPEs))
	}

	http := results[1]
	if http.Port != 80 || http.Product != "Apache httpd" {
		t.Errorf("port 80: expected Apache httpd, got %s on port %d", http.Product, http.Port)
	}
	if http.Version != "2.4.7" {
		t.Errorf("port 80: expected 2.4.7, got %s", http.Version)
	}
}

func TestParseXMLEmpty(t *testing.T) {
	results, err := ParseXML(nil, "host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(results))
	}
}

func TestParseXMLClosedPortsExcluded(t *testing.T) {
	results, _ := ParseXML([]byte(sampleXML), "scanme.nmap.org")
	for _, r := range results {
		if r.Port == 443 {
			t.Error("closed port 443 should not appear in results")
		}
	}
}

func TestBuildArgs(t *testing.T) {
	opts := DefaultOptions()
	opts.Ports = "22,80,443"
	args := BuildArgs("10.0.0.1", opts)

	contains := func(s string) bool {
		for _, a := range args {
			if a == s {
				return true
			}
		}
		return false
	}

	if !contains("-Pn") {
		t.Error("expected -Pn in args")
	}
	if !contains("-sV") {
		t.Error("expected -sV in args")
	}
	if !contains("-sT") {
		t.Error("expected -sT in args")
	}
	if !contains("22,80,443") {
		t.Error("expected port spec in args")
	}
	if !contains("10.0.0.1") {
		t.Error("expected host in args")
	}
}

func TestBuildArgsFullRange(t *testing.T) {
	opts := FullRangeOptions()
	args := BuildArgs("host", opts)

	contains := func(s string) bool {
		for _, a := range args {
			if a == s {
				return true
			}
		}
		return false
	}

	if !contains("1-65535") {
		t.Error("expected full range port spec")
	}
	if !contains("-T4") {
		t.Error("expected -T4 timing")
	}
}

func TestToFinding(t *testing.T) {
	r := Result{
		Host:    "10.0.0.1",
		Port:    22,
		Protocol: "tcp",
		Service: "ssh",
		Product: "OpenSSH",
		Version: "8.9p1",
	}
	f := r.ToFinding("10.0.0.1")
	if f.Tool != "nmap" {
		t.Errorf("expected tool=nmap, got %s", f.Tool)
	}
	if f.Port != 22 {
		t.Errorf("expected port 22, got %d", f.Port)
	}
}

func TestObservationsPortSpec(t *testing.T) {
	spec := ObservationsPortSpec([]int{22, 80, 443})
	if spec != "22,80,443" {
		t.Errorf("expected '22,80,443', got %q", spec)
	}
}
