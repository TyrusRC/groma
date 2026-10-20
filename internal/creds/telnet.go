package creds

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const telnetDialTimeout = 5 * time.Second

// CheckTelnet tries each pair against a Telnet service by reading the
// login prompt, sending credentials, and checking for success/failure
// keywords in the response. Heuristic-based: success means the response
// after password submission contains no failure keywords and looks like
// a shell prompt.
func CheckTelnet(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryTelnetLogin(ctx, addr, p)
		if err != nil {
			return nil, fmt.Errorf("creds: telnet %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "telnet", User: p.User, Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

var telnetLoginPrompts = []string{"login:", "username:"}
var telnetPassPrompts = []string{"password:"}
var telnetFailKeywords = []string{"incorrect", "denied", "failed", "invalid", "bad", "error"}

func tryTelnetLogin(ctx context.Context, addr string, p Pair) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, telnetDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()

	// Wait for login prompt.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, err := telnetReadUntilPrompt(conn, telnetLoginPrompts)
	if err != nil || !containsAnyCI(data, telnetLoginPrompts) {
		return false, nil // no login prompt → not a standard telnet login
	}

	// Send username.
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(p.User + "\r\n")); err != nil {
		return false, err
	}

	// Wait for password prompt.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, err = telnetReadUntilPrompt(conn, telnetPassPrompts)
	if err != nil || !containsAnyCI(data, telnetPassPrompts) {
		return false, nil
	}

	// Send password.
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(p.Password + "\r\n")); err != nil {
		return false, err
	}

	// Read response and check for success/failure.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if containsAnyCI(resp, telnetFailKeywords) {
		return false, nil
	}
	if containsAnyCI(resp, telnetLoginPrompts) {
		return false, nil // got another login prompt → failed
	}
	// Got some response that isn't a failure or another login prompt.
	return n > 0, nil
}

func telnetReadUntilPrompt(conn net.Conn, prompts []string) (string, error) {
	var buf [4096]byte
	var collected string
	for {
		n, err := conn.Read(buf[:])
		if n > 0 {
			collected += string(buf[:n])
			if containsAnyCI(collected, prompts) {
				return collected, nil
			}
		}
		if err != nil {
			return collected, err
		}
	}
}

func containsAnyCI(s string, needles []string) bool {
	lower := strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(lower, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
