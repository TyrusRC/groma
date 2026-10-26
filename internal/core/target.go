package core

import (
	"errors"
	"net"
	"strings"
)

// Target represents a scan target: a host (IP or hostname), optionally with
// an explicit port list. Unlike vigil's URL-based Target, groma's unit of
// work is a host, not a page.
type Target struct {
	Host  string
	Ports []int // empty = use the caller's default port list
}

// NewTarget creates a Target from a host string. Accepts a bare hostname/IP
// ("10.0.0.1", "example.com") or "host:port" (sets Ports to that one port).
func NewTarget(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("host cannot be empty")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		p, perr := parsePort(port)
		if perr != nil {
			return nil, perr
		}
		return &Target{Host: host, Ports: []int{p}}, nil
	}
	return &Target{Host: raw}, nil
}

func parsePort(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid port: " + s)
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("port out of range: " + s)
	}
	return n, nil
}
