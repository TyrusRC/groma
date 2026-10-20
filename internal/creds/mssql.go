package creds

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unicode/utf16"
)

const mssqlDialTimeout = 5 * time.Second

// CheckMSSQL tries each pair against a Microsoft SQL Server service
// using the TDS LOGIN7 packet (SQL authentication). Stops at the first
// LOGINACK response. Windows/NTLM authentication is NOT implemented.
func CheckMSSQL(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryMSSQLLogin(ctx, addr, p.User, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: mssql %s: %w", addr, err)
		}
		if ok {
			pw := p.Password
			if pw == "" {
				pw = "(none — blank password accepted)"
			}
			return &Hit{Service: "mssql", User: p.User, Password: pw}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func tryMSSQLLogin(ctx context.Context, addr, user, password string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, mssqlDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mssqlDialTimeout))

	pkt := tdsLogin7Packet(user, password)
	if _, err := conn.Write(pkt); err != nil {
		return false, fmt.Errorf("sending LOGIN7: %w", err)
	}

	// Read TDS response.
	var hdr [8]byte
	if _, err := mongoReadFull(conn, hdr[:]); err != nil {
		return false, fmt.Errorf("reading TDS header: %w", err)
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 8 || length > 65536 {
		return false, nil
	}
	payload := make([]byte, length-8)
	if _, err := mongoReadFull(conn, payload); err != nil {
		return false, nil
	}

	return tdsHasLoginAck(payload), nil
}

// tdsLogin7Packet builds a TDS 7.4 LOGIN7 packet for SQL authentication.
func tdsLogin7Packet(user, password string) []byte {
	hostname := toUTF16LE("groma")
	username := toUTF16LE(user)
	passwd := tdsObfuscatePassword(toUTF16LE(password))
	appname := toUTF16LE("groma")
	servername := toUTF16LE("")
	cltintname := toUTF16LE("ODBC")

	// Fixed header: 94 bytes.
	const fixedLen = 94
	dataStart := fixedLen

	// Calculate offsets.
	hostnameOff := uint16(dataStart)
	hostnameLen := uint16(len(hostname) / 2)
	dataStart += len(hostname)

	usernameOff := uint16(dataStart)
	usernameLen := uint16(len(username) / 2)
	dataStart += len(username)

	passwordOff := uint16(dataStart)
	passwordLen := uint16(len(passwd) / 2)
	dataStart += len(passwd)

	appnameOff := uint16(dataStart)
	appnameLen := uint16(len(appname) / 2)
	dataStart += len(appname)

	servernameOff := uint16(dataStart)
	servernameLen := uint16(len(servername) / 2)
	dataStart += len(servername)

	// Extension (unused).
	extensionOff := uint16(0)
	extensionLen := uint16(0)

	cltintOff := uint16(dataStart)
	cltintLen := uint16(len(cltintname) / 2)
	dataStart += len(cltintname)

	// Language, Database: empty.
	langOff := uint16(dataStart)
	langLen := uint16(0)
	dbOff := uint16(dataStart)
	dbLen := uint16(0)

	totalLength := uint32(dataStart)

	body := make([]byte, fixedLen)
	binary.LittleEndian.PutUint32(body[0:4], totalLength)
	binary.LittleEndian.PutUint32(body[4:8], 0x74000004)   // TDS 7.4
	binary.LittleEndian.PutUint32(body[8:12], 4096)         // packet size
	binary.LittleEndian.PutUint32(body[12:16], 0)           // client prog ver
	binary.LittleEndian.PutUint32(body[16:20], 0)           // client PID
	binary.LittleEndian.PutUint32(body[20:24], 0)           // connection ID
	body[24] = 0xE0                                          // OptionFlags1
	body[25] = 0x03                                          // OptionFlags2
	body[26] = 0x00                                          // TypeFlags
	body[27] = 0x00                                          // OptionFlags3
	binary.LittleEndian.PutUint32(body[28:32], 0)           // ClientTimZone
	binary.LittleEndian.PutUint32(body[32:36], 0x00000409)  // ClientLCID

	off := 36
	// Hostname offset/length
	binary.LittleEndian.PutUint16(body[off:off+2], hostnameOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], hostnameLen)
	off += 4
	// Username
	binary.LittleEndian.PutUint16(body[off:off+2], usernameOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], usernameLen)
	off += 4
	// Password
	binary.LittleEndian.PutUint16(body[off:off+2], passwordOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], passwordLen)
	off += 4
	// AppName
	binary.LittleEndian.PutUint16(body[off:off+2], appnameOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], appnameLen)
	off += 4
	// ServerName
	binary.LittleEndian.PutUint16(body[off:off+2], servernameOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], servernameLen)
	off += 4
	// Extension (unused)
	binary.LittleEndian.PutUint16(body[off:off+2], extensionOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], extensionLen)
	off += 4
	// CltIntName
	binary.LittleEndian.PutUint16(body[off:off+2], cltintOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], cltintLen)
	off += 4
	// Language
	binary.LittleEndian.PutUint16(body[off:off+2], langOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], langLen)
	off += 4
	// Database
	binary.LittleEndian.PutUint16(body[off:off+2], dbOff)
	binary.LittleEndian.PutUint16(body[off+2:off+4], dbLen)
	off += 4
	// ClientID (6 bytes)
	off += 6
	// SSPI offset/length
	binary.LittleEndian.PutUint16(body[off:off+2], 0)
	binary.LittleEndian.PutUint16(body[off+2:off+4], 0)
	off += 4
	// AtchDBFile offset/length
	binary.LittleEndian.PutUint16(body[off:off+2], 0)
	binary.LittleEndian.PutUint16(body[off+2:off+4], 0)
	off += 4
	// ChangePassword offset/length
	binary.LittleEndian.PutUint16(body[off:off+2], 0)
	binary.LittleEndian.PutUint16(body[off+2:off+4], 0)
	off += 4
	// SSPILong
	binary.LittleEndian.PutUint32(body[off:off+4], 0)

	// Append variable data.
	body = append(body, hostname...)
	body = append(body, username...)
	body = append(body, passwd...)
	body = append(body, appname...)
	body = append(body, servername...)
	body = append(body, cltintname...)

	// Wrap in TDS packet header.
	pktLen := 8 + len(body)
	hdr := make([]byte, 8)
	hdr[0] = 0x10 // TDS_LOGIN7
	hdr[1] = 0x01 // Status: EOM
	binary.BigEndian.PutUint16(hdr[2:4], uint16(pktLen))
	// SPID, PacketID, Window all zero.

	return append(hdr, body...)
}

// tdsObfuscatePassword applies MSSQL's password obfuscation: for each
// byte, swap high/low nibbles then XOR with 0xA5.
func tdsObfuscatePassword(utf16 []byte) []byte {
	out := make([]byte, len(utf16))
	for i, b := range utf16 {
		out[i] = ((b << 4) | (b >> 4)) ^ 0xA5
	}
	return out
}

// tdsHasLoginAck scans TDS response tokens for LOGINACK (0xAD).
func tdsHasLoginAck(payload []byte) bool {
	for _, b := range payload {
		if b == 0xAD {
			return true
		}
	}
	return false
}

func toUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
