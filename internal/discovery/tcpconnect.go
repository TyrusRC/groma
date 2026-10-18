// Package discovery finds open TCP ports and grabs any greeting banner a
// service sends unprompted. This is a plain TCP-connect scan — the baseline
// I/O primitive groma is built on, not a SYN/stealth scan or OS fingerprint
// (that needs raw sockets/root and nmap already does it well; Praetor wraps
// nmap for that deeper pass). A connect scan needs no special privileges and
// runs anywhere Go runs.
package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/sysnet"
)

const (
	defaultConcurrency = 100  // unchanged fallback if the ulimit read fails
	maxConcurrency     = 1000 // same ceiling as the naabu wrapper — a full-range connect scan is still a remote target's connection count, not just a local resource question
)

// PortResult is one port's scan outcome. Checked distinguishes "dialed
// and found closed/refused" from "never actually attempted" — the two
// look identical if a caller only reads Open, which is exactly how a
// timed-out scan used to silently under-report as "mostly closed"
// instead of "mostly unknown". See Scan's doc comment.
type PortResult struct {
	Port    int
	Open    bool
	Checked bool
	Banner  string // first line a service sent unprompted, if any (trimmed)
}

// ToFinding renders an open port as an informational core.Finding — a
// plain port-open observation, not a vulnerability on its own. Mirrors
// naabu.Result.ToFinding so a report looks the same whether naabu or
// this native fallback scanner found the port.
func (r PortResult) ToFinding(host string) *core.Finding {
	f := core.NewFinding("open_port", core.SeverityInfo)
	f.Tool = "groma"
	f.Host, f.Port, f.Protocol = host, r.Port, "tcp"
	f.Title = fmt.Sprintf("Port %d/tcp open", r.Port)
	if r.Banner != "" {
		f.Evidence = "Banner: " + r.Banner
	}
	return f
}

// DefaultPorts is a small, common-service seed list — not exhaustive (that's
// what a full nmap pass is for). Chosen for the seed detection checks this
// package currently supports (Telnet, FTP) plus the usual suspects an
// operator wants a quick signal on.
var DefaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
	445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}

// Scanner runs a concurrent TCP-connect scan against one host.
type Scanner struct {
	DialTimeout time.Duration
	BannerWait  time.Duration
	Concurrency int
}

// NewScanner returns a Scanner with sane defaults — concurrency is
// ulimit-aware (see internal/sysnet) rather than a fixed small number,
// because this scanner is groma's exhaustive full-65535-port fallback:
// at a low fixed concurrency, a full sweep against a host or network
// that drops (rather than rejects) unused ports can take many minutes,
// since every one of those ports waits out the full DialTimeout.
//
// NOTE: on a network that drops rather than rejects (measured against a
// WSL2 NAT path: ~500 ports/sec at the current concurrency/timeout
// ceiling), a full 1-65535 sweep takes ~2 minutes — comfortably inside
// the CLI's 5-minute default --timeout, but this is a real, measured
// ceiling of connect-only scanning, not a bug to keep chasing by raising
// Concurrency further. Going faster than this needs either SYN scanning
// (naabu, when installed, or nmap) or accepting more risk of looking
// like a connection flood against a real remote target — maxConcurrency
// is capped at 1000 deliberately for that reason.
func NewScanner() *Scanner {
	return &Scanner{
		DialTimeout: 2 * time.Second,
		BannerWait:  1500 * time.Millisecond,
		Concurrency: sysnet.RecommendedConcurrency(defaultConcurrency, maxConcurrency),
	}
}

// Scan connects to each port in ports (DefaultPorts if nil/empty) and
// reports which are open, with any banner grabbed. Results are returned
// in port order regardless of completion order.
//
// A non-nil error means ctx ended before every port was actually dialed
// — the Results slice is still fully populated and safe to use, but any
// entry with Checked=false was never reached: its Open=false is "status
// unknown", not "confirmed closed". Silently treating those the same
// way is exactly the failure this type distinguishes against.
func (s *Scanner) Scan(ctx context.Context, host string, ports []int) ([]PortResult, error) {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	results := make([]PortResult, len(ports))
	sem := make(chan struct{}, max(1, s.Concurrency))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(i, p int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = s.scanOne(ctx, host, p)
		}(i, p)
	}
	wg.Wait()

	unchecked := 0
	for _, r := range results {
		if !r.Checked {
			unchecked++
		}
	}
	if unchecked > 0 {
		return results, fmt.Errorf("scan incomplete: %d of %d port(s) were never reached before the context ended (status unknown, not confirmed closed)",
			unchecked, len(results))
	}
	return results, nil
}

func (s *Scanner) scanOne(ctx context.Context, host string, port int) PortResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: s.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// A dead context, not a real refusal, is the likely cause once
		// ctx has already ended — the dial may never have been attempted.
		return PortResult{Port: port, Open: false, Checked: ctx.Err() == nil}
	}
	defer conn.Close()
	r := PortResult{Port: port, Open: true, Checked: true}
	_ = conn.SetReadDeadline(time.Now().Add(s.BannerWait))
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	r.Banner = trimBanner(line)
	return r
}

func trimBanner(s string) string {
	// Strip CR/LF and cap length — a banner is a signal, not a blob to store.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < 256; i++ {
		if s[i] != '\r' && s[i] != '\n' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
