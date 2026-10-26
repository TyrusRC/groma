package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIsAliveRefusedPortCountsAsUp(t *testing.T) {
	// A listener we immediately close gives us a port that refuses
	// connections on loopback — a refusal proves the host is up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.Close()
	// 127.0.0.1 refuses on alivePorts too (nothing listening), which is
	// exactly the "up via refusal" path we want to confirm.
	if !IsAlive(context.Background(), "127.0.0.1", 500*time.Millisecond, nil) {
		t.Errorf("127.0.0.1 should be judged up (connections are refused, not dropped)")
	}
}

func TestIsAliveUnroutableIsDown(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unrouted, so every
	// probe times out and the host is down.
	if IsAlive(context.Background(), "192.0.2.1", 300*time.Millisecond, nil) {
		t.Errorf("192.0.2.1 (TEST-NET) should be judged down")
	}
}

func TestFilterAlivePreservesOrderAndDropsDead(t *testing.T) {
	hosts := []string{"192.0.2.1", "127.0.0.1", "192.0.2.2"}
	live := FilterAlive(context.Background(), hosts, 300*time.Millisecond, 4)
	if len(live) != 1 || live[0] != "127.0.0.1" {
		t.Errorf("expected only 127.0.0.1 alive, got %v", live)
	}
}
