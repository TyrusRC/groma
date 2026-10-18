package creds

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

const pgDialTimeout = 5 * time.Second

// CheckPostgres tries each pair against a PostgreSQL service using the
// wire-protocol auth methods it can actually verify: trust (no password
// requested at all), cleartext, and MD5. SCRAM-SHA-256 (the PostgreSQL
// 10+ default) is NOT implemented — a server that demands it is honestly
// reported as "not checked" (unsupported), never silently scored as "no
// default creds found".
func CheckPostgres(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		accepted, trustAuth, unsupported, err := tryPostgresLogin(ctx, addr, p.User, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: postgres %s: %w", addr, err)
		}
		if unsupported {
			return nil, nil // can't verify this server's auth method with this client
		}
		if accepted {
			pw := p.Password
			if trustAuth {
				pw = "(none — server accepted without requesting a password)"
			}
			return &Hit{Service: "postgres", User: p.User, Password: pw}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func tryPostgresLogin(ctx context.Context, addr, user, password string) (accepted, trustAuth, unsupported bool, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, pgDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, false, false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(pgDialTimeout))

	if err := pgWriteStartup(conn, user); err != nil {
		return false, false, false, fmt.Errorf("sending startup packet: %w", err)
	}
	r := bufio.NewReader(conn)

	msgType, payload, err := pgReadMessage(r)
	if err != nil {
		return false, false, false, fmt.Errorf("reading auth response: %w", err)
	}
	if msgType == 'E' {
		return false, false, false, nil // e.g. role/database doesn't exist — not a hit, not unsupported
	}
	if msgType != 'R' || len(payload) < 4 {
		return false, false, true, nil // unexpected shape — treat as unsupported rather than guessing
	}
	authCode := binary.BigEndian.Uint32(payload[0:4])

	switch authCode {
	case 0: // AuthenticationOk — accepted with no password requested at all (trust auth)
		return true, true, false, nil
	case 3: // AuthenticationCleartextPassword
		if err := pgWritePassword(conn, password); err != nil {
			return false, false, false, fmt.Errorf("sending cleartext password: %w", err)
		}
	case 5: // AuthenticationMD5Password, 4-byte salt follows
		if len(payload) < 8 {
			return false, false, true, nil
		}
		salt := payload[4:8]
		if err := pgWritePassword(conn, pgMD5Password(user, password, salt)); err != nil {
			return false, false, false, fmt.Errorf("sending md5 password: %w", err)
		}
	default:
		return false, false, true, nil // SCRAM (10) or anything else this client doesn't implement
	}

	msgType, payload, err = pgReadMessage(r)
	if err != nil {
		return false, false, false, fmt.Errorf("reading login result: %w", err)
	}
	if msgType == 'E' {
		return false, false, false, nil
	}
	if msgType == 'R' && len(payload) >= 4 && binary.BigEndian.Uint32(payload[0:4]) == 0 {
		return true, false, false, nil
	}
	return false, false, false, nil
}

// pgMD5Password implements PostgreSQL's MD5 challenge: "md5" +
// md5(hex(md5(password+user)) + salt).
func pgMD5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

func pgWriteStartup(conn net.Conn, user string) error {
	var body []byte
	body = append(body, "user\x00"+user+"\x00"...)
	body = append(body, "database\x00"+user+"\x00"...)
	body = append(body, 0x00)

	msg := make([]byte, 4, 4+4+len(body))
	binary.BigEndian.PutUint32(msg, uint32(4+4+len(body)))
	msg = append(msg, 0x00, 0x03, 0x00, 0x00) // protocol version 3.0
	msg = append(msg, body...)
	_, err := conn.Write(msg)
	return err
}

func pgWritePassword(conn net.Conn, password string) error {
	body := append([]byte(password), 0x00)
	msg := make([]byte, 5, 5+len(body))
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	msg = append(msg, body...)
	_, err := conn.Write(msg)
	return err
}

// pgReadMessage reads one backend message: a 1-byte type, a 4-byte
// length (including itself, excluding the type byte), and the payload.
func pgReadMessage(r *bufio.Reader) (byte, []byte, error) {
	msgType, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lenBuf [4]byte
	// A bare Read can short-read a 4-byte header on a real network
	// connection (bufio.Reader.Read is not guaranteed to fill the
	// buffer) — readFull loops until it does, same as the payload read
	// below already does.
	if _, err := readFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 {
		return msgType, nil, fmt.Errorf("invalid message length %d", length)
	}
	payload := make([]byte, length-4)
	if length > 4 {
		if _, err := readFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
