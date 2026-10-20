package creds

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const redisDialTimeout = 5 * time.Second

// CheckRedis probes a Redis service for default/no-auth access. It
// first tries PING without authentication — a reply of +PONG means no
// password is required at all (the most common Redis misconfiguration).
// If the server demands AUTH, each pair's Password is tried; the User
// field is used for Redis 6+ ACL mode (AUTH user pass) when a plain
// AUTH <password> fails with a wrong-number-of-arguments error.
func CheckRedis(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	noAuth, err := redisProbeNoAuth(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("creds: redis %s: %w", addr, err)
	}
	if noAuth {
		return &Hit{
			Service:  "redis",
			User:     "",
			Password: "(none — no authentication required)",
		}, nil
	}

	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryRedisAuth(ctx, addr, p)
		if err != nil {
			return nil, fmt.Errorf("creds: redis %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "redis", User: p.User, Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func redisProbeNoAuth(ctx context.Context, addr string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, redisDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(redisDialTimeout))

	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false, fmt.Errorf("sending PING: %w", err)
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("reading PING reply: %w", err)
	}
	return strings.TrimSpace(line) == "+PONG", nil
}

func tryRedisAuth(ctx context.Context, addr string, p Pair) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, redisDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(redisDialTimeout))

	r := bufio.NewReader(conn)

	// Plain AUTH <password> (Redis < 6 and 6+ without ACL).
	if _, err := fmt.Fprintf(conn, "AUTH %s\r\n", p.Password); err != nil {
		return false, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(line)
	if line == "+OK" {
		return true, nil
	}

	// Redis 6+ ACL mode: AUTH <user> <password>.
	if p.User != "" && strings.Contains(line, "wrong number of arguments") {
		conn.Close()
		dialCtx2, cancel2 := context.WithTimeout(ctx, redisDialTimeout)
		defer cancel2()
		conn2, err := (&net.Dialer{}).DialContext(dialCtx2, "tcp", addr)
		if err != nil {
			return false, err
		}
		defer conn2.Close()
		conn2.SetDeadline(time.Now().Add(redisDialTimeout))
		if _, err := fmt.Fprintf(conn2, "AUTH %s %s\r\n", p.User, p.Password); err != nil {
			return false, err
		}
		r2 := bufio.NewReader(conn2)
		line2, err := r2.ReadString('\n')
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(line2) == "+OK", nil
	}
	return false, nil
}
