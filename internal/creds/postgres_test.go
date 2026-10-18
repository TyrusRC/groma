package creds

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakePostgresServer speaks just enough of the startup/auth handshake to
// exercise CheckPostgres's cleartext and MD5 paths, and the "unsupported
// auth method" (SCRAM) honesty path.
func fakePostgresServer(t *testing.T, authMethod string, accepted Pair) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	salt := []byte{0x01, 0x02, 0x03, 0x04}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				// Read + discard the startup packet.
				var lenBuf [4]byte
				if _, err := readFull(r, lenBuf[:]); err != nil {
					return
				}
				total := binary.BigEndian.Uint32(lenBuf[:])
				rest := make([]byte, total-4)
				readFull(r, rest)
				// user is null-terminated after "user\x00" in rest; skip parsing,
				// tests only need to confirm the user they configured below.
				user := extractUser(rest)

				switch authMethod {
				case "trust":
					writeAuthOk(conn)
					return
				case "cleartext":
					writeAuthRequest(conn, 3, nil)
					pwd := readPasswordMessage(r)
					if user == accepted.User && pwd == accepted.Password {
						writeAuthOk(conn)
					} else {
						writeError(conn)
					}
				case "md5":
					writeAuthRequest(conn, 5, salt)
					pwd := readPasswordMessage(r)
					want := pgMD5Password(accepted.User, accepted.Password, salt)
					if user == accepted.User && pwd == want {
						writeAuthOk(conn)
					} else {
						writeError(conn)
					}
				case "scram":
					writeAuthRequest(conn, 10, nil) // SASL — unsupported by this client
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func extractUser(rest []byte) string {
	// rest = "user\x00<user>\x00database\x00..." — pull the value between
	// the first two null bytes after "user\x00".
	const prefix = "user\x00"
	idx := indexOf(rest, []byte(prefix))
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := indexOfByte(rest[start:], 0)
	if end < 0 {
		return ""
	}
	return string(rest[start : start+end])
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func indexOfByte(b []byte, target byte) int {
	for i, c := range b {
		if c == target {
			return i
		}
	}
	return -1
}

func writeAuthOk(conn net.Conn) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 0)
	writeMsg(conn, 'R', payload)
}

func writeAuthRequest(conn net.Conn, code uint32, extra []byte) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	payload = append(payload, extra...)
	writeMsg(conn, 'R', payload)
}

func writeError(conn net.Conn) {
	writeMsg(conn, 'E', []byte("invalid password\x00\x00"))
}

func writeMsg(conn net.Conn, msgType byte, payload []byte) {
	msg := make([]byte, 5, 5+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	msg = append(msg, payload...)
	conn.Write(msg)
}

func readPasswordMessage(r *bufio.Reader) string {
	msgType, _ := r.ReadByte()
	_ = msgType
	var lenBuf [4]byte
	readFull(r, lenBuf[:])
	length := binary.BigEndian.Uint32(lenBuf[:])
	payload := make([]byte, length-4)
	readFull(r, payload)
	// trim trailing null terminator
	if len(payload) > 0 && payload[len(payload)-1] == 0 {
		payload = payload[:len(payload)-1]
	}
	return string(payload)
}

func dialHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return host, port
}

func TestCheckPostgresTrustAuth(t *testing.T) {
	addr := fakePostgresServer(t, "trust", Pair{User: "postgres", Password: ""})
	host, port := dialHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckPostgres(ctx, host, port, DefaultPairs["postgres"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit: trust auth accepts without any password")
	}
}

func TestCheckPostgresCleartextAcceptedPair(t *testing.T) {
	accepted := Pair{User: "postgres", Password: "postgres"}
	addr := fakePostgresServer(t, "cleartext", accepted)
	host, port := dialHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckPostgres(ctx, host, port, DefaultPairs["postgres"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil || hit.User != accepted.User {
		t.Errorf("expected a hit for %+v, got %+v", accepted, hit)
	}
}

func TestCheckPostgresMD5AcceptedPair(t *testing.T) {
	accepted := Pair{User: "postgres", Password: "password"}
	addr := fakePostgresServer(t, "md5", accepted)
	host, port := dialHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckPostgres(ctx, host, port, DefaultPairs["postgres"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil || hit.User != accepted.User || hit.Password != accepted.Password {
		t.Errorf("expected a hit for %+v, got %+v", accepted, hit)
	}
}

func TestCheckPostgresScramIsHonestlyUnsupported(t *testing.T) {
	addr := fakePostgresServer(t, "scram", Pair{})
	host, port := dialHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckPostgres(ctx, host, port, DefaultPairs["postgres"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("SCRAM is not implemented — expected nil (not checked), got a hit %+v", hit)
	}
}

func TestPgMD5PasswordMatchesKnownVector(t *testing.T) {
	// Verify the algorithm independently of the fake server: md5(password+user) -> hex,
	// then md5(hex + salt) -> hex, prefixed "md5".
	user, password := "u", "p"
	salt := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...))
	want := "md5" + hex.EncodeToString(outer[:])

	if got := pgMD5Password(user, password, salt); got != want {
		t.Errorf("pgMD5Password mismatch: got %q, want %q", got, want)
	}
}
