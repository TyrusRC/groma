package creds

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const vncDialTimeout = 5 * time.Second

// CheckVNC tries each pair's Password against a VNC service using the
// RFB 3.8 authentication handshake. If the server offers security type
// 1 (None), it reports no-auth. For security type 2 (VNC
// Authentication), it DES-encrypts the 16-byte challenge with each
// password (using VNC's bit-reversed key convention). The User field is
// ignored — VNC has no username concept in the RFB protocol.
func CheckVNC(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// First probe: check for no-auth or get auth type.
	authType, err := vncProbeAuth(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("creds: vnc %s: %w", addr, err)
	}
	if authType == 1 {
		return &Hit{
			Service:  "vnc",
			User:     "",
			Password: "(none — no authentication required)",
		}, nil
	}
	if authType != 2 {
		return nil, nil // unsupported auth type
	}

	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryVNCAuth(ctx, addr, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: vnc %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "vnc", User: "", Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func vncProbeAuth(ctx context.Context, addr string) (byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, vncDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(vncDialTimeout))

	// Read server protocol version (12 bytes: "RFB 003.008\n").
	var ver [12]byte
	if _, err := mongoReadFull(conn, ver[:]); err != nil {
		return 0, fmt.Errorf("reading server version: %w", err)
	}

	// Send client version.
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return 0, err
	}

	// Read security types: count (1 byte) + types (count bytes).
	var countBuf [1]byte
	if _, err := mongoReadFull(conn, countBuf[:]); err != nil {
		return 0, err
	}
	count := int(countBuf[0])
	if count == 0 {
		return 0, fmt.Errorf("server offered zero security types (connection refused)")
	}
	types := make([]byte, count)
	if _, err := mongoReadFull(conn, types); err != nil {
		return 0, err
	}

	// Prefer None (1) if available, then VNC Auth (2).
	for _, t := range types {
		if t == 1 {
			return 1, nil
		}
	}
	for _, t := range types {
		if t == 2 {
			return 2, nil
		}
	}
	return types[0], nil // unsupported
}

func tryVNCAuth(ctx context.Context, addr, password string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, vncDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(vncDialTimeout))

	// Handshake: read version, send version.
	var ver [12]byte
	if _, err := mongoReadFull(conn, ver[:]); err != nil {
		return false, err
	}
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return false, err
	}

	// Read security types.
	var countBuf [1]byte
	if _, err := mongoReadFull(conn, countBuf[:]); err != nil {
		return false, err
	}
	types := make([]byte, int(countBuf[0]))
	if _, err := mongoReadFull(conn, types); err != nil {
		return false, err
	}

	// Select VNC Authentication (type 2).
	if _, err := conn.Write([]byte{2}); err != nil {
		return false, err
	}

	// Read 16-byte challenge.
	var challenge [16]byte
	if _, err := mongoReadFull(conn, challenge[:]); err != nil {
		return false, err
	}

	// DES-encrypt challenge with the VNC key.
	response := vncEncryptChallenge(challenge[:], password)
	if _, err := conn.Write(response); err != nil {
		return false, err
	}

	// Read 4-byte security result: 0 = OK.
	var result [4]byte
	if _, err := mongoReadFull(conn, result[:]); err != nil {
		return false, err
	}
	return binary.BigEndian.Uint32(result[:]) == 0, nil
}

// vncEncryptChallenge encrypts the 16-byte challenge using VNC's DES
// convention: password is padded/truncated to 8 bytes, each byte is
// bit-reversed, then used as a DES key for two 8-byte ECB blocks.
func vncEncryptChallenge(challenge []byte, password string) []byte {
	key := make([]byte, 8)
	for i := 0; i < 8 && i < len(password); i++ {
		key[i] = vncReverseBits(password[i])
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return make([]byte, 16) // shouldn't happen with 8-byte key
	}

	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out
}

func vncReverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out = (out << 1) | (b & 1)
		b >>= 1
	}
	return out
}
