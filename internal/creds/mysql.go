package creds

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const mysqlDialTimeout = 5 * time.Second

// CheckMySQL tries each pair against a MySQL service using the
// mysql_native_password auth handshake (SHA1-based challenge-response).
// Stops at the first accepted login. caching_sha2_password (the MySQL
// 8.0+ default) is NOT implemented — a server that demands it is
// honestly skipped, consistent with how CheckPostgres handles SCRAM.
func CheckMySQL(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		accepted, unsupported, err := tryMySQLLogin(ctx, addr, p.User, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: mysql %s: %w", addr, err)
		}
		if unsupported {
			return nil, nil
		}
		if accepted {
			pw := p.Password
			if pw == "" {
				pw = "(none — blank password accepted)"
			}
			return &Hit{Service: "mysql", User: p.User, Password: pw}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func tryMySQLLogin(ctx context.Context, addr, user, password string) (accepted, unsupported bool, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, mysqlDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mysqlDialTimeout))

	r := bufio.NewReader(conn)

	scramble, plugin, err := mysqlReadGreeting(r)
	if err != nil {
		return false, false, fmt.Errorf("reading greeting: %w", err)
	}
	if plugin != "mysql_native_password" && plugin != "" {
		return false, true, nil
	}

	var authResp []byte
	if password != "" {
		authResp = mysqlNativePassword(password, scramble)
	}

	if err := mysqlWriteAuth(conn, user, authResp); err != nil {
		return false, false, fmt.Errorf("sending auth: %w", err)
	}

	pkt, err := mysqlReadPacket(r)
	if err != nil {
		return false, false, fmt.Errorf("reading auth result: %w", err)
	}
	if len(pkt) == 0 {
		return false, false, nil
	}
	switch pkt[0] {
	case 0x00:
		return true, false, nil
	case 0xFE:
		return false, true, nil
	default:
		return false, false, nil
	}
}

func mysqlReadGreeting(r *bufio.Reader) (scramble []byte, plugin string, err error) {
	pkt, err := mysqlReadPacket(r)
	if err != nil {
		return nil, "", err
	}
	if len(pkt) < 1 {
		return nil, "", fmt.Errorf("empty greeting")
	}
	if pkt[0] == 0xFF {
		return nil, "", fmt.Errorf("server sent error on connect")
	}

	pos := 1 // skip protocol version
	nulIdx := -1
	for i := pos; i < len(pkt); i++ {
		if pkt[i] == 0 {
			nulIdx = i
			break
		}
	}
	if nulIdx < 0 || nulIdx+1+4 >= len(pkt) {
		return nil, "", fmt.Errorf("greeting too short to parse")
	}
	pos = nulIdx + 1 // past server-version NUL

	pos += 4 // connection ID

	if pos+8 > len(pkt) {
		return nil, "", fmt.Errorf("greeting too short for scramble")
	}
	scramblePart1 := make([]byte, 8)
	copy(scramblePart1, pkt[pos:pos+8])
	pos += 8

	pos++ // filler

	if pos+7 > len(pkt) {
		return scramblePart1, "", nil
	}
	pos += 2 + 1 + 2 + 2 // caps_lower + charset + status + caps_upper

	authDataLen := 0
	if pos < len(pkt) {
		authDataLen = int(pkt[pos])
		pos++
	}

	pos += 10 // reserved

	part2Len := authDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if pos+part2Len > len(pkt) {
		part2Len = len(pkt) - pos
	}
	if part2Len <= 0 {
		return scramblePart1, "", nil
	}
	scramblePart2 := make([]byte, part2Len)
	copy(scramblePart2, pkt[pos:pos+part2Len])
	pos += part2Len

	if len(scramblePart2) > 0 && scramblePart2[len(scramblePart2)-1] == 0 {
		scramblePart2 = scramblePart2[:len(scramblePart2)-1]
	}
	scramble = append(scramblePart1, scramblePart2...)

	if pos < len(pkt) {
		end := pos
		for end < len(pkt) && pkt[end] != 0 {
			end++
		}
		plugin = string(pkt[pos:end])
	}
	return scramble, plugin, nil
}

// mysqlNativePassword: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
func mysqlNativePassword(password string, scramble []byte) []byte {
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(s2[:])
	result := h.Sum(nil)
	for i := range result {
		result[i] ^= s1[i]
	}
	return result
}

func mysqlWriteAuth(conn net.Conn, user string, authResp []byte) error {
	caps := uint32(0x00000200 | 0x00008000 | 0x00080000) // PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH

	var payload []byte
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, caps)
	payload = append(payload, b4...)
	binary.LittleEndian.PutUint32(b4, 16*1024*1024)
	payload = append(payload, b4...)
	payload = append(payload, 33) // charset utf8
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0)
	payload = append(payload, byte(len(authResp)))
	payload = append(payload, authResp...)
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0)

	return mysqlWritePacket(conn, 1, payload)
}

func mysqlReadPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length == 0 {
		return nil, nil
	}
	if length > 16*1024*1024 {
		return nil, fmt.Errorf("packet too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := readFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func mysqlWritePacket(conn net.Conn, seq byte, payload []byte) error {
	hdr := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	_, err := conn.Write(append(hdr, payload...))
	return err
}
