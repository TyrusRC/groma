package discovery

import (
	"context"
	"sync"
	"time"
)

// RateLimiter caps the rate at which new connections are started across a
// scan, spreading them evenly instead of letting them burst. A burst of
// SYNs is what trips a defended host's connections-per-second threshold and
// gets a source IP blocked; evenly spacing them keeps the scan under that
// threshold. It is a plain token bucket with no burst allowance — one token
// becomes available every 1/rate, and Wait blocks for the next one.
//
// A nil *RateLimiter means "unlimited": every method is a no-op on nil, so a
// scan with no rate cap set pays nothing and the callers need no nil checks.
type RateLimiter struct {
	gap time.Duration // minimum spacing between connection starts (1/rate)

	mu   sync.Mutex
	next time.Time // earliest instant the next connection may start
}

// NewRateLimiter returns a limiter that allows at most perSec new connections
// per second, or nil (unlimited) when perSec <= 0 — so the default scan is
// uncapped and full speed.
func NewRateLimiter(perSec int) *RateLimiter {
	if perSec <= 0 {
		return nil
	}
	return &RateLimiter{gap: time.Second / time.Duration(perSec)}
}

// Wait blocks until the next connection is allowed to start, or until ctx is
// cancelled (returning ctx.Err()). It is safe for concurrent use and is a
// no-op returning nil on a nil receiver.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl == nil {
		return nil
	}

	rl.mu.Lock()
	now := time.Now()
	// Never credit time from before "now": an idle limiter must not bank up
	// a burst it then releases all at once, which would defeat the point.
	if rl.next.Before(now) {
		rl.next = now
	}
	at := rl.next
	rl.next = rl.next.Add(rl.gap)
	rl.mu.Unlock()

	delay := time.Until(at)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
