package discovery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// alivePorts is the small set of common TCP ports a host-discovery
// pre-pass knocks on to decide whether a host is worth a full scan. It's
// deliberately a broad mix (web, remote access, SMB, RDP, mail, DB) so a
// host answering on any one of them is caught.
//
// NOTE: a host firewalled to silence on every one of these ports but open
// on some unusual port will be judged "down" and skipped — the inherent
// limit of host discovery, and exactly why it is opt-in (--ping) and the
// scanner otherwise treats every target as up. This is nmap's -Pn
// tradeoff, surfaced rather than hidden.
var alivePorts = []int{80, 443, 22, 445, 3389, 8080, 21, 25, 3306, 53}

// IsAlive reports whether host answers on any common TCP port within
// timeout. A completed connection OR a refusal both mean "up" — something
// is there to respond. Only when every probe times out with no answer is
// the host treated as down. gate, when non-nil, bounds the probe
// connections against the shared global budget.
func IsAlive(ctx context.Context, host string, timeout time.Duration, gate chan struct{}) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // cancel the other probes as soon as one says "up"

	alive := make(chan struct{}, 1)
	var wg sync.WaitGroup
	for _, port := range alivePorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if gate != nil {
				select {
				case gate <- struct{}{}:
					defer func() { <-gate }()
				case <-ctx.Done():
					return
				}
			}
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				conn.Close()
				select {
				case alive <- struct{}{}:
				default:
				}
				cancel()
				return
			}
			// A refusal (or any non-timeout answer that isn't caused by
			// our own cancellation) still proves the host is reachable.
			if ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			select {
			case alive <- struct{}{}:
			default:
			}
			cancel()
		}(port)
	}
	wg.Wait()
	select {
	case <-alive:
		return true
	default:
		return false
	}
}

// FilterAlive returns the subset of hosts that answer a host-discovery
// probe, running the probes concurrently under a shared budget. Hosts
// keep their original order.
func FilterAlive(ctx context.Context, hosts []string, timeout time.Duration, hostWorkers int) []string {
	if hostWorkers < 1 {
		hostWorkers = 1
	}
	gate := make(chan struct{}, max(1, defaultConcurrency))
	results := make([]bool, len(hosts))
	pool := make(chan struct{}, hostWorkers)
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		pool <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-pool }()
			results[i] = IsAlive(ctx, host, timeout, gate)
		}(i, host)
	}
	wg.Wait()

	live := make([]string, 0, len(hosts))
	for i, up := range results {
		if up {
			live = append(live, hosts[i])
		}
	}
	return live
}

