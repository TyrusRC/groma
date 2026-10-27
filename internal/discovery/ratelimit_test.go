package discovery

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterNilAndZeroAreUnlimited(t *testing.T) {
	if NewRateLimiter(0) != nil {
		t.Error("rate 0 should mean unlimited (nil limiter)")
	}
	if NewRateLimiter(-5) != nil {
		t.Error("a negative rate should mean unlimited (nil limiter)")
	}
	var nilLimiter *RateLimiter
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := nilLimiter.Wait(context.Background()); err != nil {
			t.Fatalf("nil limiter Wait should never error: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("a nil (unlimited) limiter must not pace; 1000 waits took %v", elapsed)
	}
}

func TestRateLimiterSpacesConnections(t *testing.T) {
	const rate = 200 // 5ms gap
	rl := NewRateLimiter(rate)
	const n = 20
	gap := time.Second / rate
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := rl.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	elapsed := time.Since(start)
	// The first token is immediate; the remaining n-1 are each a gap apart.
	// Assert only the lower bound — a timer fires at or after its deadline,
	// never before, so this cannot flake on a busy machine.
	wantMin := time.Duration(n-1) * gap
	if elapsed < wantMin {
		t.Errorf("%d waits at %d/sec took %v, want at least %v — rate not enforced", n, rate, elapsed, wantMin)
	}
}

func TestRateLimiterDoesNotBankIdleTime(t *testing.T) {
	// After sitting idle, the limiter must not release a burst of tokens that
	// had "accrued" — that would spike connections and trip the very block
	// the limiter exists to avoid. Each Wait after an idle period still pays
	// at most one gap, and consecutive ones are spaced.
	rl := NewRateLimiter(100) // 10ms gap
	if err := rl.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // idle well past several gaps
	// Two waits back-to-back: the first is immediate (idle credit capped at
	// now), the second must still wait a full gap.
	start := time.Now()
	_ = rl.Wait(context.Background())
	_ = rl.Wait(context.Background())
	if elapsed := time.Since(start); elapsed < 8*time.Millisecond {
		t.Errorf("after idling, two waits took %v; the second should still pay ~one 10ms gap, not fire instantly", elapsed)
	}
}

func TestRateLimiterWaitRespectsContext(t *testing.T) {
	rl := NewRateLimiter(1) // 1s gap: the second Wait would block ~1s
	if err := rl.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if err := rl.Wait(ctx); err == nil {
		t.Error("Wait on a cancelled context should return the context error, not block then succeed")
	}
}
