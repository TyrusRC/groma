package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Status of one evaluated check.
type Status string

const (
	StatusPassed      Status = "PASSED"
	StatusFailed      Status = "FAILED"
	StatusWarning     Status = "WARNING"
	StatusUnsupported Status = "UNSUPPORTED" // check type not implemented — NOT scored as a pass
	StatusError       Status = "ERROR"       // the command/file probe itself failed to run
)

// Result is one evaluated leaf check.
type Result struct {
	Item   *CustomItem
	Status Status
	Output string // evidence: the command output or file-stat line actually observed
	Err    error
}

// Executor runs one command on the audited host over an already-
// established session (internal/audit.Dial's *ssh.Client, typically).
type Executor interface {
	RunCommand(ctx context.Context, cmd string) (output string, err error)
}

// supportedTypes lists the check types this evaluator actually executes.
// Everything else — REG_CHECK, WMI_QUERY, AUDIT_POLICY, SERVICE_POLICY,
// PASSWORD_POLICY (all Windows-only), BANNER_CHECK, PROCESS_CHECK — is
// parsed but reported as StatusUnsupported, never silently treated as a
// pass.
var supportedTypes = map[string]bool{
	"CMD_EXEC":   true,
	"FILE_CHECK": true,
}

// Evaluate walks every node in policy.Items and returns one Result per
// leaf check actually reached (an <if> whose condition didn't hold skips
// its Then branch entirely — those checks are N/A on this host, not
// failed and not evaluated at all).
func Evaluate(ctx context.Context, policy *Policy, exec Executor) ([]Result, error) {
	return evalNodes(ctx, policy.Items, exec)
}

func evalNodes(ctx context.Context, nodes []Node, exec Executor) ([]Result, error) {
	var out []Result
	for _, n := range nodes {
		switch node := n.(type) {
		case *CustomItem:
			out = append(out, evalLeaf(ctx, node, exec))
		case *IfBlock:
			results, err := evalIf(ctx, node, exec)
			if err != nil {
				return out, err
			}
			out = append(out, results...)
		default:
			return out, fmt.Errorf("compliance: unknown node type %T", n)
		}
	}
	return out, nil
}

func evalIf(ctx context.Context, ifb *IfBlock, exec Executor) ([]Result, error) {
	gate, err := evalCondition(ctx, ifb.Condition, exec)
	if err != nil {
		return nil, err
	}
	if gate {
		return evalNodes(ctx, ifb.Then, exec)
	}
	return evalNodes(ctx, ifb.Else, exec)
}

// evalCondition runs every condition item as a gate check — these are
// NEVER appended to the report's results, only used to decide Then vs
// Else. AND requires every item to come back PASSED; OR requires one.
func evalCondition(ctx context.Context, cond *ConditionBlock, exec Executor) (bool, error) {
	if cond == nil || len(cond.Items) == 0 {
		return true, nil
	}
	switch cond.Op {
	case "OR":
		for _, item := range cond.Items {
			if evalLeaf(ctx, item, exec).Status == StatusPassed {
				return true, nil
			}
		}
		return false, nil
	default: // AND
		for _, item := range cond.Items {
			if evalLeaf(ctx, item, exec).Status != StatusPassed {
				return false, nil
			}
		}
		return true, nil
	}
}

func evalLeaf(ctx context.Context, item *CustomItem, exec Executor) Result {
	if item.isReportOnly() {
		return Result{Item: item, Status: Status(item.ReportType)}
	}

	switch item.Type {
	case "CMD_EXEC":
		return evalCmdExec(ctx, item, exec)
	case "FILE_CHECK":
		return evalFileCheck(ctx, item, exec)
	default:
		return Result{Item: item, Status: StatusUnsupported}
	}
}

func evalCmdExec(ctx context.Context, item *CustomItem, exec Executor) Result {
	if item.Cmd == "" {
		return Result{Item: item, Status: StatusUnsupported}
	}
	out, err := exec.RunCommand(ctx, item.Cmd)
	if err != nil && out == "" {
		return Result{Item: item, Status: StatusError, Err: err, Output: out}
	}
	return Result{Item: item, Status: matchOutput(item, out), Output: out}
}

// matchOutput applies expect/not_expect/regex the way the real .audit
// semantics do: expect/regex must match for PASSED, not_expect must NOT
// match. A malformed regex is reported as ERROR via the caller's Err —
// here it degrades to FAILED (safer default: an unverifiable check is
// not silently a pass).
func matchOutput(item *CustomItem, out string) Status {
	out = strings.TrimSpace(out)
	if item.NotExpect != "" {
		if re, err := regexp.Compile(item.NotExpect); err == nil && re.MatchString(out) {
			return StatusFailed
		}
	}
	pattern := item.Expect
	if pattern == "" {
		pattern = item.Regex
	}
	if pattern == "" {
		// Only not_expect was set and it didn't match — that's a pass.
		if item.NotExpect != "" {
			return StatusPassed
		}
		return StatusUnsupported
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return StatusFailed
	}
	if re.MatchString(out) {
		return StatusPassed
	}
	return StatusFailed
}

// evalFileCheck runs a single portable stat command and compares the
// result against whichever of Owner/Group/Mode the check set. A missing
// file is FAILED (the common case: a CIS control requiring a file to
// exist with specific permissions) — this evaluator does not distinguish
// "file must exist" from "file must NOT exist" checks, a real gap noted
// in the README.
func evalFileCheck(ctx context.Context, item *CustomItem, exec Executor) Result {
	if item.File == "" {
		return Result{Item: item, Status: StatusUnsupported}
	}
	cmd := fmt.Sprintf(`stat -c '%%U %%G %%a' %s 2>/dev/null || echo MISSING`, shellQuote(item.File))
	out, err := exec.RunCommand(ctx, cmd)
	if err != nil {
		return Result{Item: item, Status: StatusError, Err: err, Output: out}
	}
	out = strings.TrimSpace(out)
	if out == "MISSING" || out == "" {
		return Result{Item: item, Status: StatusFailed, Output: out}
	}
	fields := strings.Fields(out)
	if len(fields) != 3 {
		return Result{Item: item, Status: StatusError, Output: out, Err: fmt.Errorf("unexpected stat output %q", out)}
	}
	owner, group, mode := fields[0], fields[1], fields[2]
	if item.Owner != "" && !strings.EqualFold(owner, item.Owner) {
		return Result{Item: item, Status: StatusFailed, Output: out}
	}
	if item.Group != "" && !strings.EqualFold(group, item.Group) {
		return Result{Item: item, Status: StatusFailed, Output: out}
	}
	if item.Mode != "" && !modeMatches(mode, item.Mode) {
		return Result{Item: item, Status: StatusFailed, Output: out}
	}
	return Result{Item: item, Status: StatusPassed, Output: out}
}

// modeMatches compares octal permission strings numerically ("644" ==
// "0644"), not lexically.
func modeMatches(got, want string) bool {
	g, err1 := strconv.ParseInt(got, 8, 32)
	w, err2 := strconv.ParseInt(want, 8, 32)
	if err1 != nil || err2 != nil {
		return got == want
	}
	return g == w
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}
