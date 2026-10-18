// Package compliance implements a pragmatic, verified subset of Tenable's
// proprietary `.audit` CIS/DISA-STIG compliance-check format, run against
// an already-established SSH session (internal/audit.Dial).
//
// The format itself (angle-bracket blocks, <if>/<condition>/<then>/<else>
// control flow, <custom_item> check leaves) was reverse-engineered from a
// real nessusd build — see AUDIT_VPR_SCHEDULING.md in the project's
// reverse-engineering notes for the exact grammar and the CIS AIX example
// this parser's tests are drawn from. Only the two check types that cover
// the overwhelming majority of real Unix CIS/STIG content are executed:
// CMD_EXEC (run a command, regex-match the output) and FILE_CHECK (file
// existence/owner/group/mode). Windows-only types (REG_CHECK, WMI_QUERY,
// AUDIT_POLICY, SERVICE_POLICY, PASSWORD_POLICY) and a couple of rarer
// Unix ones (BANNER_CHECK, PROCESS_CHECK) are parsed but evaluate to an
// explicit UNSUPPORTED result rather than being silently skipped or
// scored as a pass — "honest about what it didn't check" is the same
// rule internal/discovery and internal/tools/naabu already follow for a
// scan that didn't reach every port.
//
// This is deliberately NOT a full .audit interpreter: no @VARIABLE@
// substitution, no nested if-inside-condition, no nested if-inside-then
// beyond one level, no nested if inside a <report> block. A real-world
// audit using those constructs parses as far as it can and reports a
// clear error, rather than silently mis-evaluating.
package compliance

import (
	"fmt"
	"regexp"
	"strings"
)

// CustomItem is one leaf check — either a real test (Type/Cmd/Expect set)
// or an unconditional report emission (ReportType set, no Cmd).
type CustomItem struct {
	Type        string // CMD_EXEC, FILE_CHECK, REG_CHECK, BANNER_CHECK, PROCESS_CHECK, ...
	Description string
	Info        string
	Solution    string
	Reference   string
	SeeAlso     string
	System      string

	Cmd       string
	Expect    string
	NotExpect string
	Regex     string

	File  string
	Owner string
	Group string
	Mode  string

	// ReportType is set only for a <report type:"PASSED|FAILED|WARNING">
	// block, which has no check logic of its own — reaching it in control
	// flow always emits that status.
	ReportType string
}

func (c *CustomItem) isReportOnly() bool { return c.ReportType != "" && c.Cmd == "" && c.File == "" }

// ConditionBlock gates an IfBlock's Then/Else branch. AND requires every
// item to PASS; OR requires at least one.
type ConditionBlock struct {
	Op    string // "AND" | "OR"
	Items []*CustomItem
}

// IfBlock is one <if>/<condition>/<then>/<else> control-flow node.
type IfBlock struct {
	Condition *ConditionBlock
	Then      []Node
	Else      []Node
}

// Node is either a *CustomItem (a leaf check) or an *IfBlock (control flow).
type Node any

// Policy is one parsed .audit file.
type Policy struct {
	CheckType string // "Unix", "Windows", ...
	Items     []Node
}

// Parse parses raw .audit text into a Policy. Lines starting with '#'
// (including the embedded #<ui_metadata> block, which is documentation,
// not executable content) are skipped entirely.
func Parse(raw string) (*Policy, error) {
	toks, err := tokenize(raw)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}

	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("compliance: empty audit file")
	}
	first, ok := p.toks[p.pos].(openTagTok)
	if !ok || first.name != "check_type" {
		return nil, fmt.Errorf("compliance: expected <check_type:\"...\"> as the first directive")
	}
	p.pos++

	items, err := p.parseNodes("")
	if err != nil {
		return nil, err
	}
	return &Policy{CheckType: first.attrVal, Items: items}, nil
}

// --- tokenizer -------------------------------------------------------

type token any

type openTagTok struct {
	name    string
	attrKey string
	attrVal string
}
type closeTagTok struct{ name string }
type kvTok struct{ key, val string }

var openTagRe = regexp.MustCompile(`^<([A-Za-z_]+)(?:\s+([A-Za-z_]+)\s*:\s*"([^"]*)"|:\s*"([^"]*)")?\s*>$`)
var closeTagRe = regexp.MustCompile(`^</([A-Za-z_]+)>$`)

func tokenize(raw string) ([]token, error) {
	var toks []token
	for n, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := closeTagRe.FindStringSubmatch(line); m != nil {
			toks = append(toks, closeTagTok{name: m[1]})
			continue
		}
		if m := openTagRe.FindStringSubmatch(line); m != nil {
			t := openTagTok{name: m[1]}
			if m[2] != "" {
				t.attrKey, t.attrVal = m[2], m[3]
			} else {
				t.attrVal = m[4]
			}
			toks = append(toks, t)
			continue
		}
		if strings.HasPrefix(line, "<") {
			return nil, fmt.Errorf("compliance: line %d: unparseable tag: %q", n+1, line)
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("compliance: line %d: expected key:value, got %q", n+1, line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.TrimPrefix(val, `"`)
		val = strings.TrimSuffix(val, `"`)
		toks = append(toks, kvTok{key: key, val: val})
	}
	return toks, nil
}

// --- recursive-descent parser ----------------------------------------

type parser struct {
	toks []token
	pos  int
}

// parseNodes consumes nodes until a close tag named stop (stop=="" means
// "until EOF" — used only at the policy's top level).
func (p *parser) parseNodes(stop string) ([]Node, error) {
	var nodes []Node
	for p.pos < len(p.toks) {
		switch t := p.toks[p.pos].(type) {
		case closeTagTok:
			if t.name == stop {
				p.pos++
				return nodes, nil
			}
			return nil, fmt.Errorf("compliance: unexpected </%s> (expected </%s>)", t.name, stop)
		case openTagTok:
			switch t.name {
			case "if":
				p.pos++
				ifb, err := p.parseIf()
				if err != nil {
					return nil, err
				}
				nodes = append(nodes, ifb)
			case "custom_item":
				p.pos++
				item, err := p.parseLeaf("custom_item")
				if err != nil {
					return nil, err
				}
				nodes = append(nodes, item)
			case "report":
				p.pos++
				item, err := p.parseLeaf("report")
				if err != nil {
					return nil, err
				}
				item.ReportType = t.attrVal
				nodes = append(nodes, item)
			default:
				return nil, fmt.Errorf("compliance: unexpected <%s> here", t.name)
			}
		case kvTok:
			return nil, fmt.Errorf("compliance: unexpected key:value %q outside a block", t.key)
		}
	}
	if stop != "" {
		return nil, fmt.Errorf("compliance: missing closing </%s>", stop)
	}
	return nodes, nil
}

func (p *parser) parseIf() (*IfBlock, error) {
	cond, err := p.expectCondition()
	if err != nil {
		return nil, err
	}
	thenNodes, err := p.expectBranch("then")
	if err != nil {
		return nil, err
	}
	ifb := &IfBlock{Condition: cond, Then: thenNodes}

	if p.pos < len(p.toks) {
		if t, ok := p.toks[p.pos].(openTagTok); ok && t.name == "else" {
			p.pos++
			elseNodes, err := p.parseNodes("else")
			if err != nil {
				return nil, err
			}
			ifb.Else = elseNodes
		}
	}

	if err := p.expectClose("if"); err != nil {
		return nil, err
	}
	return ifb, nil
}

func (p *parser) expectCondition() (*ConditionBlock, error) {
	t, ok := p.next().(openTagTok)
	if !ok || t.name != "condition" {
		return nil, fmt.Errorf("compliance: <if> must open with <condition type:\"AND|OR\">")
	}
	op := strings.ToUpper(t.attrVal)
	if op == "" {
		op = "AND"
	}
	nodes, err := p.parseNodes("condition")
	if err != nil {
		return nil, err
	}
	items := make([]*CustomItem, 0, len(nodes))
	for _, n := range nodes {
		item, ok := n.(*CustomItem)
		if !ok || item.isReportOnly() {
			return nil, fmt.Errorf("compliance: <condition> may only contain <custom_item> checks, not <report>")
		}
		items = append(items, item)
	}
	return &ConditionBlock{Op: op, Items: items}, nil
}

func (p *parser) expectBranch(name string) ([]Node, error) {
	t, ok := p.next().(openTagTok)
	if !ok || t.name != name {
		return nil, fmt.Errorf("compliance: expected <%s> here", name)
	}
	return p.parseNodes(name)
}

func (p *parser) expectClose(name string) error {
	t, ok := p.next().(closeTagTok)
	if !ok || t.name != name {
		return fmt.Errorf("compliance: expected </%s>", name)
	}
	return nil
}

func (p *parser) next() token {
	if p.pos >= len(p.toks) {
		return nil
	}
	t := p.toks[p.pos]
	p.pos++
	return t
}

// parseLeaf reads key:value attribute lines into a CustomItem until the
// matching close tag.
func (p *parser) parseLeaf(closeName string) (*CustomItem, error) {
	item := &CustomItem{}
	for {
		if p.pos >= len(p.toks) {
			return nil, fmt.Errorf("compliance: missing </%s>", closeName)
		}
		if t, ok := p.toks[p.pos].(closeTagTok); ok {
			if t.name != closeName {
				return nil, fmt.Errorf("compliance: expected </%s>, got </%s>", closeName, t.name)
			}
			p.pos++
			return item, nil
		}
		kv, ok := p.toks[p.pos].(kvTok)
		if !ok {
			return nil, fmt.Errorf("compliance: expected a key:value attribute inside <%s>", closeName)
		}
		p.pos++
		applyKV(item, kv.key, kv.val)
	}
}

func applyKV(item *CustomItem, key, val string) {
	switch strings.ToLower(key) {
	case "type":
		item.Type = val
	case "description":
		item.Description = val
	case "info":
		item.Info = val
	case "solution":
		item.Solution = val
	case "reference":
		item.Reference = val
	case "see_also":
		item.SeeAlso = val
	case "system":
		item.System = val
	case "cmd":
		item.Cmd = val
	case "expect":
		item.Expect = val
	case "not_expect":
		item.NotExpect = val
	case "regex":
		item.Regex = val
	case "file":
		item.File = val
	case "owner":
		item.Owner = val
	case "group":
		item.Group = val
	case "mode":
		item.Mode = val
	default:
		// Unknown/forward-looking attribute (e.g. value_type, value_data on
		// REG_CHECK) — ignored, not fatal. The audit still parses; the
		// check type's own evaluator decides what it needs.
	}
}
