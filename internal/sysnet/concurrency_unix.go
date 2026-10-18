//go:build !windows

package sysnet

import "syscall"

// RecommendedConcurrency reads the process's open-file-descriptor limit
// and returns a worker count comfortably under it, bounded to
// [defaultN, maxN] — the same "don't out-run your own file descriptors"
// lesson RustScan's auto-batch-sizing applies, reimplemented natively
// here rather than vendored. Leaves roughly half the limit as headroom
// for stdio, the caller's own sockets, and DNS.
func RecommendedConcurrency(defaultN, maxN int) int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return defaultN
	}
	limit := int(rl.Cur)
	if limit <= 0 {
		return defaultN
	}
	safe := limit / 2
	if safe < defaultN {
		return defaultN
	}
	if safe > maxN {
		return maxN
	}
	return safe
}
