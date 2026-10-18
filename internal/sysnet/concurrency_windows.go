//go:build windows

package sysnet

// RecommendedConcurrency has no ulimit concept on Windows; fall back to
// the caller's own static default.
func RecommendedConcurrency(defaultN, _ int) int { return defaultN }
