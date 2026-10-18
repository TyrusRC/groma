package sysnet

import "testing"

func TestRecommendedConcurrencyWithinBounds(t *testing.T) {
	c := RecommendedConcurrency(100, 1000)
	if c < 100 || c > 1000 {
		t.Errorf("RecommendedConcurrency(100, 1000) = %d, want within [100, 1000]", c)
	}
}

func TestRecommendedConcurrencyNeverBelowDefault(t *testing.T) {
	// Even a pathologically low max must not push the result below the
	// caller's own stated floor.
	c := RecommendedConcurrency(50, 50)
	if c != 50 {
		t.Errorf("RecommendedConcurrency(50, 50) = %d, want 50", c)
	}
}
