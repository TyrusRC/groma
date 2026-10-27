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
	"errors"
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
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443,
	445, 587, 636, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306,
	3389, 5432, 5672, 5678, 5900, 5984, 6333, 6379, 6443, 8080,
	8443, 8500, 8888, 9000, 9090, 9200, 9443, 11211, 11434, 15672,
	27017,
}

// Scanner runs a concurrent TCP-connect scan against one host.
type Scanner struct {
	DialTimeout time.Duration
	BannerWait  time.Duration
	Concurrency int

	// Retries is the number of EXTRA dial attempts made when a connect
	// times out (a dropped SYN on a lossy path). A refused/reset/
	// unreachable answer is definitive and never retried. Without this a
	// single dropped probe silently reports a genuinely-open port as
	// closed — the "missed port" failure that makes a one-shot scan
	// untrustworthy.
	Retries int

	// Gate, when non-nil, is a shared concurrency budget used INSTEAD of
	// an internal per-host semaphore. The multi-host scan path passes one
	// gate to every per-host Scanner so the total number of in-flight
	// connections is bounded globally, not per host — N hosts each with
	// their own budget would be N× the connection count against the
	// network and can exhaust file descriptors.
	Gate chan struct{}

	// Limiter, when non-nil, caps the rate at which NEW connections are
	// started, spread evenly rather than bursted. It is shared across hosts
	// like Gate. Gate bounds how many connections are in flight at once;
	// Limiter bounds how fast new ones are opened — the distinction that
	// matters against a target whose defenses trip on connections-per-second
	// (a rate-based block) rather than on concurrent count. Off (nil) by
	// default, so a normal scan runs at full speed; set it only for a host
	// that must be probed gently.
	Limiter *RateLimiter
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
		// 3s matches the naabu wrapper's connect timeout: a high-latency or
		// SYN-rate-limited host often does not complete the handshake inside
		// 2s, and since this scanner is also the verifier for ports naabu
		// found nothing on, too short a timeout here would repeat naabu's
		// blind spot. Retries stays at 1 — a second attempt rides out a
		// single dropped packet without multiplying the wait on every
		// filtered port, which a higher count would.
		DialTimeout: 3 * time.Second,
		BannerWait:  1500 * time.Millisecond,
		Concurrency: sysnet.RecommendedConcurrency(defaultConcurrency, maxConcurrency),
		Retries:     1,
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
	sem := s.Gate
	if sem == nil {
		sem = make(chan struct{}, max(1, s.Concurrency))
	}
	var wg sync.WaitGroup
	for i, p := range ports {
		// Pace new connections before taking a concurrency slot. On ctx end
		// the remaining ports stay Checked=false and surface as incomplete.
		if err := s.Limiter.Wait(ctx); err != nil {
			break
		}
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
	attempts := 1 + max(0, s.Retries)
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			// Context ended before this attempt — the port was never
			// actually reached, so its status is unknown, not closed.
			return PortResult{Port: port, Open: false, Checked: false}
		}
		d := net.Dialer{Timeout: s.DialTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			r := PortResult{Port: port, Open: true, Checked: true}
			_ = conn.SetReadDeadline(time.Now().Add(s.BannerWait))
			line, _ := bufio.NewReader(conn).ReadString('\n')
			r.Banner = trimBanner(line)
			conn.Close()
			return r
		}
		if ctx.Err() != nil {
			return PortResult{Port: port, Open: false, Checked: false}
		}
		// A timeout is the only retryable outcome: on a dropping path a
		// genuinely-open port can swallow one SYN. A refused/reset/
		// unreachable answer is definitive — the port is closed, and
		// retrying only wastes time, so return immediately.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return PortResult{Port: port, Open: false, Checked: true}
	}
	// Every attempt timed out: the port is filtered/dropped. We did fully
	// attempt it, so this is a confirmed negative, not "never reached".
	return PortResult{Port: port, Open: false, Checked: true}
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
