package compliance

import "testing"

// This exact snippet is quoted verbatim in the project's reverse-
// engineering notes (AUDIT_VPR_SCHEDULING.md, section "3. .audit File
// Format"), extracted from a real nessusd build's audit warehouse — not
// a guessed shape.
const cisAIXExample = `
#<ui_metadata>
#<display_name>CIS AIX 5.3/6.1 L1 v1.1.0</display_name>
#</ui_metadata>
<check_type:"Unix">

<if>
  <condition type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "AIX 5.3 or 6.1 is installed"
      cmd         : "/usr/bin/oslevel -s"
      expect      : "^(5300|6100)"
    </custom_item>
  </condition>
  <then>
    <report type:"PASSED">
      description : "CIS AIX 5.3 and 6.1 v1.1.0 Level 1"
      reference   : "800-171|3.4.1,800-53|CM-8a.1.,CSF|DE.CM-7"
    </report>

    <custom_item>
      system      : "AIX"
      type        : CMD_EXEC
      description : "1.1.1 - /etc/security/user - 'mindiff >= 4'"
      info        : "Checks the minimum number of characters"
      reference   : "800-171|3.5.7,800-53|IA-5(1)(b),CSF|PR.AC-1,LEVEL|1S"
      see_also    : "https://workbench.cisecurity.org/files/525"
      cmd         : "/usr/bin/lssec -f /etc/security/user -s default -a mindiff"
      expect      : "^default[\s]+mindiff[\s]*=[\s]*[4-8]$"
    </custom_item>
  </then>
</if>
`

func TestParseCISAIXExample(t *testing.T) {
	policy, err := Parse(cisAIXExample)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if policy.CheckType != "Unix" {
		t.Errorf("expected CheckType=Unix, got %q", policy.CheckType)
	}
	if len(policy.Items) != 1 {
		t.Fatalf("expected exactly one top-level node (the <if>), got %d", len(policy.Items))
	}
	ifb, ok := policy.Items[0].(*IfBlock)
	if !ok {
		t.Fatalf("expected the top-level node to be an *IfBlock, got %T", policy.Items[0])
	}
	if ifb.Condition.Op != "AND" || len(ifb.Condition.Items) != 1 {
		t.Fatalf("expected one AND-gated condition item, got %+v", ifb.Condition)
	}
	if ifb.Condition.Items[0].Cmd != "/usr/bin/oslevel -s" {
		t.Errorf("condition item cmd mismapped: %+v", ifb.Condition.Items[0])
	}
	if len(ifb.Then) != 2 {
		t.Fatalf("expected 2 nodes in <then> (the report + the real check), got %d", len(ifb.Then))
	}
	report, ok := ifb.Then[0].(*CustomItem)
	if !ok || report.ReportType != "PASSED" || !report.isReportOnly() {
		t.Errorf("expected the first <then> node to be an unconditional PASSED report, got %+v", ifb.Then[0])
	}
	real, ok := ifb.Then[1].(*CustomItem)
	if !ok || real.Type != "CMD_EXEC" || real.Description != "1.1.1 - /etc/security/user - 'mindiff >= 4'" {
		t.Errorf("real check item mismapped: %+v", ifb.Then[1])
	}
	if real.Expect != `^default[\s]+mindiff[\s]*=[\s]*[4-8]$` {
		t.Errorf("expect regex mismapped: got %q", real.Expect)
	}
}

func TestParseRejectsUnclosedBlock(t *testing.T) {
	_, err := Parse(`<check_type:"Unix"><if><condition type:"AND"><custom_item>
type: CMD_EXEC
cmd: "echo hi"
expect: "hi"
</custom_item></condition><then>`)
	if err == nil {
		t.Fatal("expected an error for a missing </then></if>, not a silently truncated policy")
	}
}

func TestParseRejectsConditionWithNonCustomItem(t *testing.T) {
	_, err := Parse(`<check_type:"Unix">
<if>
<condition type:"AND">
<report type:"PASSED">
description: "not allowed here"
</report>
</condition>
<then>
</then>
</if>`)
	if err == nil {
		t.Fatal("expected an error: <condition> may only contain <custom_item>, not <report>")
	}
}
