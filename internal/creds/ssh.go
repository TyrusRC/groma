package creds

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// CheckSSH tries each pair against an SSH service and stops at the first
// accepted login. Host key verification is intentionally skipped here —
// unlike internal/audit's credentialed pass (a real admin session using
// real operator credentials, which DOES verify the host key), this is a
// one-shot probe using a publicly known default password against a host
// the operator already targeted; a relayed probe reveals nothing the
// scan didn't already know. Trading that verification away buys a check
// that works on a freshly discovered, never-before-seen host.
func CheckSSH(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conf := &ssh.ClientConfig{
			User:            p.User,
			Auth:            []ssh.AuthMethod{ssh.Password(p.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}
		dialCtx, cancel := context.WithTimeout(ctx, conf.Timeout)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("creds: dialing %s: %w", addr, err)
		}
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, conf)
		if err == nil {
			client := ssh.NewClient(sshConn, chans, reqs)
			client.Close()
			return &Hit{Service: "ssh", User: p.User, Password: p.Password}, nil
		}
		conn.Close()
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}
