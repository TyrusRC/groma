package creds

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeMongoDBServer speaks just enough OP_MSG to respond to a ping
// command. If noAuth is true, the reply is {ok: 1}; otherwise it
// returns an auth-required error.
func fakeMongoDBServer(t *testing.T, noAuth bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Read request header (16 bytes).
				var hdr [16]byte
				if _, err := mongoReadFull(conn, hdr[:]); err != nil {
					return
				}
				reqLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
				if reqLen < 16 {
					return
				}
				body := make([]byte, reqLen-16)
				if _, err := mongoReadFull(conn, body); err != nil {
					return
				}

				reqID := binary.LittleEndian.Uint32(hdr[4:8])

				var respBSON []byte
				if noAuth {
					respBSON = fakeMongoOkBSON()
				} else {
					respBSON = fakeMongoErrBSON()
				}

				// Build OP_MSG response.
				opMsg := make([]byte, 4+1+len(respBSON))
				opMsg[4] = 0 // section kind 0
				copy(opMsg[5:], respBSON)

				totalLen := 16 + len(opMsg)
				respHdr := make([]byte, 16)
				binary.LittleEndian.PutUint32(respHdr[0:4], uint32(totalLen))
				binary.LittleEndian.PutUint32(respHdr[4:8], 2)    // responseTo's requestID
				binary.LittleEndian.PutUint32(respHdr[8:12], reqID) // responseTo
				binary.LittleEndian.PutUint32(respHdr[12:16], 2013) // OP_MSG

				conn.Write(append(respHdr, opMsg...))
			}()
		}
	}()
	return ln.Addr().String()
}

// fakeMongoOkBSON builds {ok: 1.0} as BSON.
func fakeMongoOkBSON() []byte {
	var doc []byte
	doc = append(doc, 0, 0, 0, 0) // length placeholder
	doc = append(doc, 0x01)        // type: double
	doc = append(doc, "ok\x00"...) // key
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, math.Float64bits(1.0))
	doc = append(doc, b8...)
	doc = append(doc, 0x00) // terminator
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	return doc
}

// fakeMongoErrBSON builds {ok: 0.0, errmsg: "auth required"} as BSON.
func fakeMongoErrBSON() []byte {
	var doc []byte
	doc = append(doc, 0, 0, 0, 0) // length placeholder
	doc = append(doc, 0x01)        // type: double
	doc = append(doc, "ok\x00"...) // key
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, math.Float64bits(0.0))
	doc = append(doc, b8...)
	// errmsg: "auth required"
	doc = append(doc, 0x02)            // type: string
	doc = append(doc, "errmsg\x00"...) // key
	msg := "auth required\x00"
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, uint32(len(msg)))
	doc = append(doc, b4...)
	doc = append(doc, msg...)
	doc = append(doc, 0x00) // terminator
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	return doc
}

func TestCheckMongoDBNoAuth(t *testing.T) {
	addr := fakeMongoDBServer(t, true)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMongoDB(ctx, host, port, DefaultPairs["mongodb"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for no-auth MongoDB")
	}
	if hit.Service != "mongodb" {
		t.Errorf("expected service mongodb, got %s", hit.Service)
	}
}

func TestCheckMongoDBAuthRequired(t *testing.T) {
	addr := fakeMongoDBServer(t, false)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMongoDB(ctx, host, port, DefaultPairs["mongodb"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit when auth is required, got %+v", hit)
	}
}

func TestMongoCheckOkWithDouble(t *testing.T) {
	bson := fakeMongoOkBSON()
	if !mongoCheckOk(bson) {
		t.Error("expected mongoCheckOk to return true for {ok: 1.0}")
	}
}

func TestMongoCheckOkWithInt32(t *testing.T) {
	var doc []byte
	doc = append(doc, 0, 0, 0, 0)
	doc = append(doc, 0x10) // int32
	doc = append(doc, "ok\x00"...)
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, 1)
	doc = append(doc, b4...)
	doc = append(doc, 0x00)
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	if !mongoCheckOk(doc) {
		t.Error("expected mongoCheckOk to return true for {ok: int32(1)}")
	}
}

func TestMongoCheckOkFailure(t *testing.T) {
	bson := fakeMongoErrBSON()
	if mongoCheckOk(bson) {
		t.Error("expected mongoCheckOk to return false for {ok: 0.0}")
	}
}
