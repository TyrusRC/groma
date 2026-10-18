package discovery

import "testing"

func TestPortResultToFindingIsInformational(t *testing.T) {
	r := PortResult{Port: 22, Open: true, Banner: "SSH-2.0-OpenSSH_9.6"}
	f := r.ToFinding("10.0.0.5")
	if f.Severity != "info" {
		t.Errorf("a raw open-port observation is recon, not a vulnerability — expected info severity, got %s", f.Severity)
	}
	if f.Host != "10.0.0.5" || f.Port != 22 || f.Protocol != "tcp" {
		t.Errorf("location fields mismapped: %+v", f)
	}
	if f.Evidence != "Banner: SSH-2.0-OpenSSH_9.6" {
		t.Errorf("expected evidence to carry the banner, got %q", f.Evidence)
	}
}
