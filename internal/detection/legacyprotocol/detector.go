// Package legacyprotocol holds groma's SEED detection checks — a small,
// deliberately narrow starting set of well-established, zero-ambiguity
// network misconfigurations. groma's real detection-engine scope (what a
// mature network scanner checks beyond this) is intentionally deferred
// pending the operator's own OpenVAS/Tenable research — this package is not
// meant to grow ad hoc ahead of that; see README.md.
package legacyprotocol

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/discovery"
)

// Detect runs the seed checks against the ports a discovery scan found open,
// and returns any findings. Never returns an error for a check that simply
// found nothing — only for a context cancellation.
func Detect(ctx context.Context, host string, results []discovery.PortResult) []*core.Finding {
	var findings []*core.Finding
	for _, r := range results {
		if !r.Open {
			continue
		}
		switch r.Port {
		case 23:
			findings = append(findings, telnetExposed(host, r))
		case 21:
			if f := ftpAnonymousLogin(ctx, host, r); f != nil {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// telnetExposed flags an open Telnet port — a cleartext remote-admin
// protocol with no transport encryption by design (not a scan artifact to
// confirm further; the exposure IS the finding). Severity reflects "a
// cleartext admin channel is reachable", not "credentials are known".
func telnetExposed(host string, r discovery.PortResult) *core.Finding {
	f := core.NewFinding("telnet_exposed", core.SeverityMedium)
	f.Tool = "groma"
	f.Title = "Telnet service exposed"
	f.Description = "Port 23 (Telnet) is open. Telnet transmits all traffic, " +
		"including credentials, in cleartext — anyone able to observe the " +
		"network path can recover them."
	f.Host, f.Port, f.Protocol, f.Service = host, r.Port, "tcp", "telnet"
	if r.Banner != "" {
		f.Evidence = "Service banner: " + r.Banner
	} else {
		f.Evidence = "TCP connect to port 23 succeeded."
	}
	f.CWE = []string{"CWE-319"} // Cleartext Transmission of Sensitive Information
	f.Remediation = "Disable Telnet; use SSH (port 22) for remote administration."
	return f
}

// ftpAnonymousLogin actively confirms whether the FTP server accepts the
// RFC 959 anonymous-login convention — a real, bounded, non-destructive
// control test (anonymous FTP is a deliberate guest-access mechanism; this
// checks whether it is lef on when it shouldn't be, the same class as Rule 6
// auth-control testing in Praetor's hunting rules, not unauthorized access
// to a real person's account).
func ftpAnonymousLogin(ctx context.Context, host string, r discovery.PortResult) *core.Finding {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", r.Port))
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil // port was open moments ago but isn't now — not a finding either way
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting banner

	if _, err := conn.Write([]byte("USER anonymous\r\n")); err != nil {
		return nil
	}
	userResp, _ := reader.ReadString('\n')
	if _, err := conn.Write([]byte("PASS anonymous@example.com\r\n")); err != nil {
		return nil
	}
	passResp, _ := reader.ReadString('\n')
	_, _ = conn.Write([]byte("QUIT\r\n"))

	// 230 = login successful. 331 on USER is normal (asking for a password);
	// the real signal is PASS returning 230 rather than 530 (not logged in).
	if strings.HasPrefix(strings.TrimSpace(passResp), "230") {
		f := core.NewFinding("ftp_anonymous_login", core.SeverityLow)
		f.Tool = "groma"
		f.Title = "FTP anonymous login accepted"
		f.Description = "The FTP server accepts the anonymous/guest login convention."
		f.Host, f.Port, f.Protocol, f.Service = host, r.Port, "tcp", "ftp"
		f.Evidence = fmt.Sprintf("USER anonymous -> %s | PASS ... -> %s",
			strings.TrimSpace(userResp), strings.TrimSpace(passResp))
		f.CWE = []string{"CWE-287"} // Improper Authentication
		f.Remediation = "Disable anonymous FTP unless intentionally serving public files; " +
			"if intentional, confirm the anonymous account cannot write or escape its chroot."
		return f
	}
	return nil
}
