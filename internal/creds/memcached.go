package creds

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const memcachedDialTimeout = 5 * time.Second

// CheckMemcached probes a Memcached service for unauthenticated access.
// Sends "stats\r\n" — a reply with STAT lines means no authentication
// is required. Like CheckMongoDB, this ignores the pair list.
func CheckMemcached(ctx context.Context, host string, port int, _ []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialCtx, cancel := context.WithTimeout(ctx, memcachedDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("creds: memcached %s: dialing: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		return nil, fmt.Errorf("creds: memcached %s: sending stats: %w", addr, err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil // read error = can't determine, not a finding
	}
	resp := string(buf[:n])

	if strings.Contains(resp, "STAT ") {
		return &Hit{
			Service:  "memcached",
			User:     "",
			Password: "(none — no authentication required)",
		}, nil
	}
	return nil, nil
}
