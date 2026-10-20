package creds

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

const mongoDialTimeout = 5 * time.Second

// CheckMongoDB probes a MongoDB service for unauthenticated access — the
// most common MongoDB misconfiguration (auth disabled entirely, the
// default before MongoDB 6.0). It sends an OP_MSG {ping:1} to the admin
// database; a successful reply means no authentication is required.
//
// SCRAM-SHA-1/256 username/password testing is NOT implemented — the
// protocol is complex and the overwhelming majority of "default MongoDB"
// findings in the wild are no-auth, not weak-password. The pair list
// exists so the dispatcher knows this service has a checker.
func CheckMongoDB(ctx context.Context, host string, port int, _ []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	noAuth, err := mongoProbeNoAuth(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("creds: mongodb %s: %w", addr, err)
	}
	if noAuth {
		return &Hit{
			Service:  "mongodb",
			User:     "",
			Password: "(none — no authentication required)",
		}, nil
	}
	return nil, nil
}

func mongoProbeNoAuth(ctx context.Context, addr string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, mongoDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mongoDialTimeout))

	msg := mongoBuildPing()
	if _, err := conn.Write(msg); err != nil {
		return false, fmt.Errorf("sending ping: %w", err)
	}

	var hdr [16]byte
	if _, err := mongoReadFull(conn, hdr[:]); err != nil {
		return false, fmt.Errorf("reading response header: %w", err)
	}

	respLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
	if respLen < 16 || respLen > 48*1024*1024 {
		return false, nil
	}

	body := make([]byte, respLen-16)
	if _, err := mongoReadFull(conn, body); err != nil {
		return false, nil
	}

	opCode := binary.LittleEndian.Uint32(hdr[12:16])
	if opCode != 2013 {
		return false, nil
	}

	// OP_MSG body: flags(4) + section_kind(1) + BSON document
	if len(body) < 5 {
		return false, nil
	}
	bson := body[5:]
	return mongoCheckOk(bson), nil
}

// mongoCheckOk scans a BSON document for "ok" with a numeric value of 1.
func mongoCheckOk(doc []byte) bool {
	if len(doc) < 5 {
		return false
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen > len(doc) {
		docLen = len(doc)
	}
	pos := 4
	for pos < docLen-1 {
		if pos >= len(doc) {
			break
		}
		elemType := doc[pos]
		pos++
		nameStart := pos
		for pos < len(doc) && doc[pos] != 0 {
			pos++
		}
		if pos >= len(doc) {
			break
		}
		name := string(doc[nameStart:pos])
		pos++ // skip NUL

		switch elemType {
		case 0x01: // double (8 bytes)
			if pos+8 > len(doc) {
				return false
			}
			if name == "ok" {
				bits := binary.LittleEndian.Uint64(doc[pos : pos+8])
				return math.Float64frombits(bits) == 1.0
			}
			pos += 8
		case 0x10: // int32 (4 bytes)
			if pos+4 > len(doc) {
				return false
			}
			if name == "ok" {
				return int32(binary.LittleEndian.Uint32(doc[pos:pos+4])) == 1
			}
			pos += 4
		case 0x12: // int64 (8 bytes)
			if pos+8 > len(doc) {
				return false
			}
			if name == "ok" {
				return int64(binary.LittleEndian.Uint64(doc[pos:pos+8])) == 1
			}
			pos += 8
		case 0x02: // string
			if pos+4 > len(doc) {
				return false
			}
			sLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4 + sLen
		case 0x03, 0x04: // document / array
			if pos+4 > len(doc) {
				return false
			}
			dLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += dLen
		case 0x08: // boolean
			pos++
		case 0x07: // ObjectId
			pos += 12
		case 0x09, 0x11: // datetime / timestamp
			pos += 8
		case 0x0A: // null
			// zero-length
		default:
			return false
		}
	}
	return false
}

func mongoBuildPing() []byte {
	bson := mongoBuildPingBSON()

	opMsg := make([]byte, 4+1+len(bson))
	// flags = 0 (first 4 bytes already zero)
	opMsg[4] = 0 // section kind 0 (body)
	copy(opMsg[5:], bson)

	totalLen := 16 + len(opMsg)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(hdr[4:8], 1)    // requestID
	binary.LittleEndian.PutUint32(hdr[12:16], 2013) // OP_MSG

	return append(hdr, opMsg...)
}

func mongoBuildPingBSON() []byte {
	var doc []byte
	doc = append(doc, 0, 0, 0, 0) // length placeholder

	// ping: int32(1)
	doc = append(doc, 0x10)
	doc = append(doc, "ping\x00"...)
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, 1)
	doc = append(doc, b4...)

	// $db: "admin"
	doc = append(doc, 0x02)
	doc = append(doc, "$db\x00"...)
	binary.LittleEndian.PutUint32(b4, 6) // len("admin") + NUL
	doc = append(doc, b4...)
	doc = append(doc, "admin\x00"...)

	doc = append(doc, 0x00) // terminator
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	return doc
}

func mongoReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
