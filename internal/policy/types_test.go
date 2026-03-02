package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildSummary_empty(t *testing.T) {
	r := &Report{}
	s := r.BuildSummary(DefaultPolicy(), "audit")
	require.Equal(t, 0, s.Total)
	require.Equal(t, 0, s.High)
	require.Equal(t, 0, s.Medium)
	require.Equal(t, 0, s.Low)
	require.True(t, s.Passed)
}

func TestBuildSummary_counts(t *testing.T) {
	r := &Report{Violations: []Violation{
		{RuleID: "A", Severity: SeverityHigh},
		{RuleID: "B", Severity: SeverityHigh},
		{RuleID: "C", Severity: SeverityMedium},
		{RuleID: "D", Severity: SeverityLow},
	}}
	s := r.BuildSummary(DefaultPolicy(), "audit")
	require.Equal(t, 4, s.Total)
	require.Equal(t, 2, s.High)
	require.Equal(t, 1, s.Medium)
	require.Equal(t, 1, s.Low)
}

func TestShouldFail(t *testing.T) {
	highViolation := []Violation{{RuleID: "X", Severity: SeverityHigh}}
	mediumViolation := []Violation{{RuleID: "X", Severity: SeverityMedium}}
	p := DefaultPolicy() // fail_on: ["HIGH"]

	// audit mode never triggers failure
	require.False(t, (&Report{Violations: highViolation}).ShouldFail(p, "audit"))

	// preissuance: HIGH matches fail_on → should fail
	require.True(t, (&Report{Violations: highViolation}).ShouldFail(p, "preissuance"))

	// preissuance: MEDIUM not in fail_on → should not fail
	require.False(t, (&Report{Violations: mediumViolation}).ShouldFail(p, "preissuance"))

	// no violations → no failure
	require.False(t, (&Report{}).ShouldFail(p, "preissuance"))
}

func TestJSON_structure(t *testing.T) {
	r := &Report{}
	out, err := r.JSON(DefaultPolicy(), "audit")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))

	// violations must be an empty array, not null
	violations, ok := parsed["violations"].([]interface{})
	require.True(t, ok)
	require.Empty(t, violations)
}

func TestJSON_withViolation(t *testing.T) {
	r := &Report{Violations: []Violation{
		{RuleID: "TEST-001", Severity: SeverityHigh, Message: "something broke", Standard: "RFC5280"},
	}}
	out, err := r.JSON(DefaultPolicy(), "audit")
	require.NoError(t, err)
	require.Contains(t, out, "TEST-001")
	require.Contains(t, out, "HIGH")
	require.Contains(t, out, "something broke")
}

func TestJSON_passedField(t *testing.T) {
	p := DefaultPolicy()

	// no violations in preissuance → passed=true
	out, err := (&Report{}).JSON(p, "preissuance")
	require.NoError(t, err)
	var clean map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &clean))
	require.Equal(t, true, clean["summary"].(map[string]interface{})["passed"])

	// HIGH violation in preissuance → passed=false
	out, err = (&Report{Violations: []Violation{{RuleID: "A", Severity: SeverityHigh}}}).JSON(p, "preissuance")
	require.NoError(t, err)
	var failing map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &failing))
	require.Equal(t, false, failing["summary"].(map[string]interface{})["passed"])
}

func TestJSON_detailsNotInOutput(t *testing.T) {
	r := &Report{Details: "Key Type: RSA\n", Violations: []Violation{}}
	out, err := r.JSON(DefaultPolicy(), "audit")
	require.NoError(t, err)
	require.NotContains(t, out, "Key Type: RSA")
}

func TestReportString_noViolations(t *testing.T) {
	require.Contains(t, (&Report{}).String(), "No policy violations found")
}

func TestReportString_withViolation(t *testing.T) {
	r := &Report{Violations: []Violation{
		{RuleID: "RULE-001", Severity: SeverityHigh, Message: "something bad", Standard: "RFC5280"},
	}}
	s := r.String()
	require.Contains(t, s, "RULE-001")
	require.Contains(t, s, "HIGH")
	require.Contains(t, s, "something bad")
}

func TestReportString_includesDetails(t *testing.T) {
	r := &Report{
		Details:    "Key Type: RSA, Key Size: 2048 bits\n",
		Violations: []Violation{},
	}
	require.Contains(t, r.String(), "Key Type: RSA")
}