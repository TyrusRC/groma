package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	probeTimeout    = 5 * time.Second
	probeBannerWait = 2 * time.Second
	probeWorkers    = 20
)

// ProbeResults runs active service probes on already-discovered open ports.
// This implements the core nmap technique: connect, optionally send a
// protocol-specific probe, read the response, and match it against known
// service patterns. Enriches PortResults with Banner data and returns
// ServiceInfo for each identified service.
//
// Probe order per port (same priority as nmap):
//  1. NULL probe: connect and wait for a spontaneous banner (SSH, FTP, SMTP, etc.)
//  2. HTTP probe: send GET request, parse Server header
//  3. TLS probe: negotiate TLS, extract certificate common name / subject
func ProbeResults(ctx context.Context, host string, results []PortResult) map[int]*ServiceInfo {
	services := map[int]*ServiceInfo{}
	var mu sync.Mutex

	sem := make(chan struct{}, probeWorkers)
	var wg sync.WaitGroup

	for i := range results {
		if !results[i].Open {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(r *PortResult) {
			defer wg.Done()
			defer func() { <-sem }()

			si := probePort(ctx, host, r)
			if si != nil {
				mu.Lock()
				services[r.Port] = si
				mu.Unlock()
			}
		}(&results[i])
	}
	wg.Wait()
	return services
}

func probePort(ctx context.Context, host string, r *PortResult) *ServiceInfo {
	// Phase 1: Try to fingerprint from existing banner (from the scan's
	// passive banner grab). Cheapest — no extra connection.
	if r.Banner != "" {
		if si := FingerprintBanner(r.Banner); si != nil {
			return si
		}
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", r.Port))

	// Phase 2: Active NULL probe — connect and wait for a banner the
	// passive grab might have missed (longer wait, clean connection).
	if si := probeNull(ctx, addr, r); si != nil {
		return si
	}

	// Phase 3: HTTP probe — send a GET request. Most web services don't
	// send banners spontaneously.
	if si := probeHTTP(ctx, addr, r); si != nil {
		return si
	}

	// Phase 4: TLS probe — try a TLS handshake to identify HTTPS services
	// and extract certificate info.
	if si := probeTLS(ctx, addr, r); si != nil {
		return si
	}

	// Phase 5: Fall back to port-based guess.
	svc := FingerprintByPort(r.Port)
	if svc != "" {
		return &ServiceInfo{Product: svc}
	}
	return nil
}

// probeNull connects and waits for a spontaneous banner.
func probeNull(ctx context.Context, addr string, r *PortResult) *ServiceInfo {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(probeBannerWait))

	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	banner := trimBanner(line)
	if banner != "" {
		r.Banner = banner
		return FingerprintBanner(banner)
	}
	return nil
}

// probeHTTP sends an HTTP GET request and parses the response.
func probeHTTP(ctx context.Context, addr string, r *PortResult) *ServiceInfo {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))

	host, _, _ := net.SplitHostPort(addr)
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: groma/1.0\r\nAccept: */*\r\n\r\n", host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}

	reader := bufio.NewReader(conn)
	var serverHeader string
	var poweredBy string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break // end of headers
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			serverHeader = strings.TrimSpace(line[7:])
		}
		if strings.HasPrefix(lower, "x-powered-by:") {
			poweredBy = strings.TrimSpace(line[13:])
		}
	}

	if serverHeader != "" {
		// Try to fingerprint from the Server header.
		if si := FingerprintBanner("Server: " + serverHeader); si != nil {
			r.Banner = "Server: " + serverHeader
			return si
		}
		// Even without a match, record it.
		r.Banner = "Server: " + serverHeader
		return &ServiceInfo{Product: serverHeader}
	}
	if poweredBy != "" {
		return &ServiceInfo{Product: poweredBy}
	}
	return nil
}

// probeTLS tries a TLS handshake. If it succeeds, the port serves TLS.
func probeTLS(ctx context.Context, addr string, r *PortResult) *ServiceInfo {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostFromAddr(addr),
	})
	tlsConn.SetDeadline(time.Now().Add(probeTimeout))

	if err := tlsConn.Handshake(); err != nil {
		return nil
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cn := state.PeerCertificates[0].Subject.CommonName
		if cn != "" {
			r.Banner = "TLS CN: " + cn
		}
	}

	// Try HTTP over TLS.
	host := hostFromAddr(addr)
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: groma/1.0\r\nAccept: */*\r\n\r\n", host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return &ServiceInfo{Product: "https"}
	}

	reader := bufio.NewReader(tlsConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			serverHeader := strings.TrimSpace(line[7:])
			r.Banner = "Server: " + serverHeader
			if si := FingerprintBanner("Server: " + serverHeader); si != nil {
				return si
			}
			return &ServiceInfo{Product: serverHeader}
		}
	}
	return &ServiceInfo{Product: "https"}
}

func hostFromAddr(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
