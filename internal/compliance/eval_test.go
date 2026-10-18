package compliance

import (
	"context"
	"testing"
)

// fakeExecutor returns a canned output for each command, keyed exactly.
type fakeExecutor struct {
	outputs map[string]string
	errs    map[string]error
	calls   []string
}

func (f *fakeExecutor) RunCommand(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	return f.outputs[cmd], f.errs[cmd]
}

func TestEvalCmdExecPassAndFail(t *testing.T) {
	exec := &fakeExecutor{outputs: map[string]string{
		"pass-cmd": "yes",
		"fail-cmd": "no",
	}}
	pass := evalLeaf(context.Background(), &CustomItem{Type: "CMD_EXEC", Cmd: "pass-cmd", Expect: "^yes$"}, exec)
	if pass.Status != StatusPassed {
		t.Errorf("expected PASSED, got %s", pass.Status)
	}
	fail := evalLeaf(context.Background(), &CustomItem{Type: "CMD_EXEC", Cmd: "fail-cmd", Expect: "^yes$"}, exec)
	if fail.Status != StatusFailed {
		t.Errorf("expected FAILED, got %s", fail.Status)
	}
}

func TestEvalCmdExecNotExpect(t *testing.T) {
	exec := &fakeExecutor{outputs: map[string]string{"c": "telnet enabled"}}
	r := evalLeaf(context.Background(), &CustomItem{Type: "CMD_EXEC", Cmd: "c", NotExpect: "telnet"}, exec)
	if r.Status != StatusFailed {
		t.Errorf("not_expect matching the output must FAIL the check, got %s", r.Status)
	}
}

func TestEvalUnsupportedTypeNeverScoresAsPass(t *testing.T) {
	exec := &fakeExecutor{}
	r := evalLeaf(context.Background(), &CustomItem{Type: "REG_CHECK"}, exec)
	if r.Status != StatusUnsupported {
		t.Errorf("an unimplemented check type must report UNSUPPORTED, never PASSED/FAILED, got %s", r.Status)
	}
	if len(exec.calls) != 0 {
		t.Errorf("an unsupported check type must never execute a command, got calls %v", exec.calls)
	}
}

func TestEvalReportOnlyEmitsUnconditionally(t *testing.T) {
	exec := &fakeExecutor{}
	r := evalLeaf(context.Background(), &CustomItem{ReportType: "PASSED", Description: "info banner"}, exec)
	if r.Status != StatusPassed {
		t.Errorf("expected the report block's own type to be emitted directly, got %s", r.Status)
	}
	if len(exec.calls) != 0 {
		t.Errorf("a report-only item must never run a command, got calls %v", exec.calls)
	}
}

func TestEvalFileCheckMissingFileFails(t *testing.T) {
	exec := &fakeExecutor{outputs: map[string]string{
		`stat -c '%U %G %a' '/etc/nonexistent' 2>/dev/null || echo MISSING`: "MISSING",
	}}
	r := evalFileCheck(context.Background(), &CustomItem{Type: "FILE_CHECK", File: "/etc/nonexistent", Owner: "root"}, exec)
	if r.Status != StatusFailed {
		t.Errorf("a missing file a check requires to exist must FAIL, got %s", r.Status)
	}
}

func TestEvalFileCheckOwnerGroupModeMatch(t *testing.T) {
	cmd := `stat -c '%U %G %a' '/etc/shadow' 2>/dev/null || echo MISSING`
	exec := &fakeExecutor{outputs: map[string]string{cmd: "root shadow 640"}}
	item := &CustomItem{Type: "FILE_CHECK", File: "/etc/shadow", Owner: "root", Group: "shadow", Mode: "0640"}
	r := evalFileCheck(context.Background(), item, exec)
	if r.Status != StatusPassed {
		t.Errorf("expected PASSED for a matching owner/group/mode (640 vs want 0640, numeric compare), got %s: %+v", r.Status, r)
	}
}

func TestEvalFileCheckModeMismatchFails(t *testing.T) {
	cmd := `stat -c '%U %G %a' '/etc/shadow' 2>/dev/null || echo MISSING`
	exec := &fakeExecutor{outputs: map[string]string{cmd: "root shadow 644"}}
	item := &CustomItem{Type: "FILE_CHECK", File: "/etc/shadow", Mode: "0640"}
	r := evalFileCheck(context.Background(), item, exec)
	if r.Status != StatusFailed {
		t.Errorf("expected FAILED for mode 644 vs required 0640, got %s", r.Status)
	}
}

func TestEvaluateIfElseRunsThenWhenConditionPasses(t *testing.T) {
	exec := &fakeExecutor{outputs: map[string]string{
		"check-os": "linux",
	}}
	policy := &Policy{CheckType: "Unix", Items: []Node{
		&IfBlock{
			Condition: &ConditionBlock{Op: "AND", Items: []*CustomItem{
				{Type: "CMD_EXEC", Cmd: "check-os", Expect: "linux"},
			}},
			Then: []Node{&CustomItem{Type: "CMD_EXEC", Cmd: "real-check", Expect: "ok", Description: "then-branch"}},
			Else: []Node{&CustomItem{Type: "CMD_EXEC", Cmd: "else-check", Expect: "ok", Description: "else-branch"}},
		},
	}}
	exec.outputs["real-check"] = "ok"
	results, err := Evaluate(context.Background(), policy, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].Item.Description != "then-branch" {
		t.Fatalf("expected exactly the then-branch result, got %+v", results)
	}
	for _, c := range exec.calls {
		if c == "else-check" {
			t.Errorf("else-check must never run when the condition passed")
		}
	}
}

func TestEvaluateConditionGatesNeverAppearInResults(t *testing.T) {
	exec := &fakeExecutor{outputs: map[string]string{"gate": "match"}}
	policy := &Policy{CheckType: "Unix", Items: []Node{
		&IfBlock{
			Condition: &ConditionBlock{Op: "AND", Items: []*CustomItem{
				{Type: "CMD_EXEC", Cmd: "gate", Expect: "match", Description: "gate-item"},
			}},
			Then: nil,
		},
	}}
	results, err := Evaluate(context.Background(), policy, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range results {
		if r.Item != nil && r.Item.Description == "gate-item" {
			t.Errorf("a condition gate item must never be reported as a finding-eligible result")
		}
	}
}

func TestToFindingsSkipsPassedAndUnsupported(t *testing.T) {
	results := []Result{
		{Item: &CustomItem{Description: "ok"}, Status: StatusPassed},
		{Item: &CustomItem{Description: "no reg support", Type: "REG_CHECK"}, Status: StatusUnsupported},
		{Item: &CustomItem{Description: "bad mode", Type: "FILE_CHECK", Solution: "chmod 600"}, Status: StatusFailed},
	}
	findings, unsupported, errored := ToFindings("10.0.0.5", results)
	if len(findings) != 1 || findings[0].Title != "bad mode" {
		t.Fatalf("expected exactly 1 finding (the FAILED one), got %+v", findings)
	}
	if len(unsupported) != 1 {
		t.Fatalf("expected the UNSUPPORTED result surfaced separately (never silently dropped), got %d", len(unsupported))
	}
	if len(errored) != 0 {
		t.Fatalf("expected no errored results, got %d", len(errored))
	}
	if findings[0].Remediation != "chmod 600" {
		t.Errorf("expected remediation to carry through, got %q", findings[0].Remediation)
	}
}
