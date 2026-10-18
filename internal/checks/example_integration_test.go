package checks

import "testing"

func TestExampleCheckFileLoadsAndMatches(t *testing.T) {
	loaded, err := LoadChecks("../../checks/examples")
	if err != nil {
		t.Fatalf("failed to load shipped example checks: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("expected at least one example check to load")
	}
	var apache *Check
	for _, c := range loaded {
		if c.ID == "CVE-2021-41773" {
			apache = c
		}
	}
	if apache == nil {
		t.Fatal("expected the CVE-2021-41773 example check to load")
	}
	if !apache.Matches(Observation{Product: "apache", Version: "2.4.50"}) {
		t.Error("the shipped example check must match the vulnerable version it documents")
	}
	if apache.Matches(Observation{Product: "apache", Version: "2.4.51"}) {
		t.Error("the shipped example check must not match the patched version")
	}
}
