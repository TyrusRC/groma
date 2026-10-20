package creds

import (
	"context"
	"fmt"
	"net"
	"time"
)

const ldapDialTimeout = 5 * time.Second

// CheckLDAP tries each pair against an LDAP service using a Simple Bind
// (LDAPv3). The User field is the bind DN (e.g. "cn=admin,dc=example,dc=com").
// A BindResponse with resultCode 0 = success, 49 = invalidCredentials.
func CheckLDAP(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := tryLDAPBind(ctx, addr, p.User, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: ldap %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "ldap", User: p.User, Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func tryLDAPBind(ctx context.Context, addr, dn, password string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, ldapDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(ldapDialTimeout))

	pkt := ldapBuildBindRequest(1, dn, password)
	if _, err := conn.Write(pkt); err != nil {
		return false, fmt.Errorf("sending bind request: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, fmt.Errorf("reading bind response: %w", err)
	}

	return ldapParseBindResult(buf[:n]) == 0, nil
}

// ldapBuildBindRequest builds an LDAPv3 SimpleBind request:
//
//	LDAPMessage ::= SEQUENCE {
//	  messageID  INTEGER,
//	  protocolOp BindRequest ::= [APPLICATION 0] SEQUENCE {
//	    version INTEGER (3),
//	    name    OCTET STRING (DN),
//	    authentication [0] OCTET STRING (password)
//	  }
//	}
func ldapBuildBindRequest(msgID int, dn, password string) []byte {
	// version INTEGER 3
	version := ldapBERInt(3)
	// name OCTET STRING
	name := berOctetString([]byte(dn))
	// authentication: context-specific [0] (simple auth)
	auth := berTagLenVal(0x80, []byte(password))

	bindReqContent := append(version, name...)
	bindReqContent = append(bindReqContent, auth...)
	// BindRequest: APPLICATION 0, constructed = 0x60
	bindReq := berTagLenVal(0x60, bindReqContent)

	messageID := ldapBERInt(msgID)
	msgContent := append(messageID, bindReq...)

	return berSequence(msgContent)
}

// ldapParseBindResult extracts the resultCode from a BindResponse.
// Returns -1 on parse failure.
func ldapParseBindResult(data []byte) int {
	if len(data) < 2 || data[0] != 0x30 {
		return -1
	}
	// Outer SEQUENCE.
	_, content := berParseTL(data)
	if content == nil {
		return -1
	}
	// Skip messageID INTEGER.
	_, content = berSkipElement(content)
	if content == nil {
		return -1
	}
	// BindResponse: APPLICATION 1 = 0x61.
	if len(content) < 1 || content[0] != 0x61 {
		return -1
	}
	_, brContent := berParseTL(content)
	if brContent == nil {
		return -1
	}
	// First element of BindResponse is resultCode (ENUMERATED, tag 0x0A).
	if len(brContent) < 3 || brContent[0] != 0x0A {
		return -1
	}
	_, val := berParseTL(brContent)
	if val == nil || len(val) == 0 {
		return -1
	}
	return int(val[0])
}

func ldapBERInt(v int) []byte {
	if v < 128 {
		return berInteger([]byte{byte(v)})
	}
	// Multi-byte integer encoding.
	var raw []byte
	n := v
	for n > 0 {
		raw = append([]byte{byte(n & 0xFF)}, raw...)
		n >>= 8
	}
	return berInteger(raw)
}
