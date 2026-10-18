package creds

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const ftpDialTimeout = 5 * time.Second

// CheckFTP tries each pair against an FTP service (RFC 959 USER/PASS)
// and stops at the first "230" (logged in) reply.
func CheckFTP(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryFTPLogin(ctx, addr, p)
		if err != nil {
			return nil, fmt.Errorf("creds: ftp %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "ftp", User: p.User, Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func tryFTPLogin(ctx context.Context, addr string, p Pair) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, ftpDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(ftpDialTimeout))

	r := bufio.NewReader(conn)
	if _, _, err := ftpReply(r); err != nil { // banner
		return false, fmt.Errorf("reading banner: %w", err)
	}

	if err := ftpSend(conn, "USER "+p.User); err != nil {
		return false, err
	}
	code, _, err := ftpReply(r)
	if err != nil {
		return false, fmt.Errorf("reading USER reply: %w", err)
	}
	if code == 230 {
		return true, nil // server logged the user in without a password
	}
	if code != 331 { // 331 = "need password"
		return false, nil
	}

	if err := ftpSend(conn, "PASS "+p.Password); err != nil {
		return false, err
	}
	code, _, err = ftpReply(r)
	if err != nil {
		return false, fmt.Errorf("reading PASS reply: %w", err)
	}
	return code == 230, nil
}

func ftpSend(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

// ftpReply reads one FTP reply line and parses its 3-digit status code.
// Multi-line replies ("230-...") are not followed — the status code on
// the first line is enough to decide success/failure here.
func ftpReply(r *bufio.Reader) (int, string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, line, fmt.Errorf("reply too short: %q", line)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, line, fmt.Errorf("non-numeric reply code: %q", line)
	}
	return code, line, nil
}
