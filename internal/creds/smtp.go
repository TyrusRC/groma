package creds

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

const smtpDialTimeout = 5 * time.Second

// CheckSMTP probes an SMTP service for weak AUTH credentials or open
// relay. It sends EHLO, checks for AUTH capability, and tries AUTH
// PLAIN with each pair. If no AUTH is advertised, it checks for open
// relay via MAIL FROM / RCPT TO.
func CheckSMTP(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// First probe: check capabilities.
	hasAuth, err := smtpHasAuth(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("creds: smtp %s: %w", addr, err)
	}

	if !hasAuth {
		// Check for open relay.
		relay, err := smtpCheckOpenRelay(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("creds: smtp %s: %w", addr, err)
		}
		if relay {
			return &Hit{
				Service:  "smtp",
				User:     "",
				Password: "(open relay — no authentication required)",
			}, nil
		}
		return nil, nil
	}

	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := trySMTPAuth(ctx, addr, p)
		if err != nil {
			return nil, fmt.Errorf("creds: smtp %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "smtp", User: p.User, Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func smtpDial(ctx context.Context, addr string) (net.Conn, *bufio.Reader, error) {
	dialCtx, cancel := context.WithTimeout(ctx, smtpDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dialing: %w", err)
	}
	conn.SetDeadline(time.Now().Add(smtpDialTimeout))
	r := bufio.NewReader(conn)
	// Read 220 banner.
	line, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("reading banner: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected banner: %s", strings.TrimSpace(line))
	}
	return conn, r, nil
}

func smtpHasAuth(ctx context.Context, addr string) (bool, error) {
	conn, r, err := smtpDial(ctx, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("EHLO groma\r\n")); err != nil {
		return false, err
	}
	return smtpReadEHLOAuth(r)
}

func smtpReadEHLOAuth(r *bufio.Reader) (bool, error) {
	hasAuth := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return false, err
		}
		if strings.Contains(strings.ToUpper(line), "AUTH") {
			hasAuth = true
		}
		// "250 " (space, not dash) marks last line.
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return hasAuth, nil
}

func trySMTPAuth(ctx context.Context, addr string, p Pair) (bool, error) {
	conn, r, err := smtpDial(ctx, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("EHLO groma\r\n")); err != nil {
		return false, err
	}
	if _, err := smtpReadEHLOAuth(r); err != nil {
		return false, err
	}

	// AUTH PLAIN: base64(\x00user\x00password)
	plain := "\x00" + p.User + "\x00" + p.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	if _, err := fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", encoded); err != nil {
		return false, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(line), "235"), nil
}

func smtpCheckOpenRelay(ctx context.Context, addr string) (bool, error) {
	conn, r, err := smtpDial(ctx, addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("EHLO groma\r\n")); err != nil {
		return false, err
	}
	// Consume EHLO response.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return false, err
		}
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	if _, err := conn.Write([]byte("MAIL FROM:<test@example.com>\r\n")); err != nil {
		return false, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(line, "250") {
		return false, nil
	}

	if _, err := conn.Write([]byte("RCPT TO:<test@example.org>\r\n")); err != nil {
		return false, err
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return false, err
	}
	conn.Write([]byte("RSET\r\n"))
	conn.Write([]byte("QUIT\r\n"))
	return strings.HasPrefix(line, "250"), nil
}
