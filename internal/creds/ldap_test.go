package creds

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func fakeLDAPServer(t *testing.T, acceptedDN, acceptedPass string) string {
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
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil || n == 0 {
					return
				}

				dn, pass := fakeLDAPExtractBind(buf[:n])
				var resultCode byte
				if dn == acceptedDN && pass == acceptedPass {
					resultCode = 0 // success
				} else {
					resultCode = 49 // invalidCredentials
				}
				resp := fakeLDAPBuildBindResponse(1, resultCode)
				conn.Write(resp)
			}()
		}
	}()
	return ln.Addr().String()
}

func fakeLDAPExtractBind(data []byte) (dn, password string) {
	if len(data) < 2 || data[0] != 0x30 {
		return "", ""
	}
	_, content := berParseTL(data)
	if content == nil {
		return "", ""
	}
	// Skip messageID.
	_, content = berSkipElement(content)
	if content == nil {
		return "", ""
	}
	// BindRequest: 0x60.
	if len(content) < 1 || content[0] != 0x60 {
		return "", ""
	}
	_, brContent := berParseTL(content)
	if brContent == nil {
		return "", ""
	}
	// Skip version INTEGER.
	_, brContent = berSkipElement(brContent)
	if brContent == nil {
		return "", ""
	}
	// DN: OCTET STRING (0x04).
	if len(brContent) < 2 || brContent[0] != 0x04 {
		return "", ""
	}
	_, dnVal := berParseTL(brContent)
	_, brContent = berSkipElement(brContent)
	if brContent == nil {
		return string(dnVal), ""
	}
	// Password: context-specific [0] (0x80).
	if len(brContent) < 2 || brContent[0] != 0x80 {
		return string(dnVal), ""
	}
	_, passVal := berParseTL(brContent)
	return string(dnVal), string(passVal)
}

func fakeLDAPBuildBindResponse(msgID int, resultCode byte) []byte {
	messageID := ldapBERInt(msgID)
	// resultCode: ENUMERATED (tag 0x0A)
	rc := berTagLenVal(0x0A, []byte{resultCode})
	// matchedDN: empty OCTET STRING
	matchedDN := berOctetString(nil)
	// diagnosticMessage: empty OCTET STRING
	diagMsg := berOctetString(nil)
	brContent := append(rc, matchedDN...)
	brContent = append(brContent, diagMsg...)
	bindResp := berTagLenVal(0x61, brContent)
	msgContent := append(messageID, bindResp...)
	return berSequence(msgContent)
}

func TestCheckLDAPAccepted(t *testing.T) {
	addr := fakeLDAPServer(t, "cn=admin,dc=example,dc=com", "admin")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pairs := []Pair{{"cn=admin,dc=example,dc=com", "admin"}}
	hit, err := CheckLDAP(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for accepted bind")
	}
	if hit.User != "cn=admin,dc=example,dc=com" {
		t.Errorf("expected accepted DN, got %q", hit.User)
	}
}

func TestCheckLDAPRejected(t *testing.T) {
	addr := fakeLDAPServer(t, "cn=admin,dc=example,dc=com", "secret")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pairs := []Pair{{"cn=admin,dc=example,dc=com", "wrong"}}
	hit, err := CheckLDAP(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}
