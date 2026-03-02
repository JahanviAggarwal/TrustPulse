package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Violation struct {
	RuleID   string   `json:"rule_id"`
	Standard string   `json:"standard"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Summary holds aggregate violation counts for a single audit run.
type Summary struct {
	Total  int  `json:"total"`
	High   int  `json:"high"`
	Medium int  `json:"medium"`
	Low    int  `json:"low"`
	Passed bool `json:"passed"`
}

// jsonReport is the JSON-serialisable form of a Report.
// It intentionally excludes raw cert/CSR detail text.
type jsonReport struct {
	Summary    Summary     `json:"summary"`
	Violations []Violation `json:"violations"`
}

// Report collects violations from a single audit run together with the
// human-readable certificate/CSR detail block used in text output.
type Report struct {
	Violations []Violation
	Details    string
}

// BuildSummary counts violations by severity and determines whether the run
// should be considered passing given the current policy and run mode.
func (r *Report) BuildSummary(p *Policy, runMode string) Summary {
	s := Summary{Total: len(r.Violations)}
	for _, v := range r.Violations {
		switch v.Severity {
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		}
	}
	s.Passed = !r.ShouldFail(p, runMode)
	return s
}

// JSON returns the report as indented JSON. Violations is always an array
// (never null) so downstream consumers don't need nil checks.
func (r *Report) JSON(p *Policy, runMode string) (string, error) {
	jr := jsonReport{
		Summary:    r.BuildSummary(p, runMode),
		Violations: r.Violations,
	}
	if jr.Violations == nil {
		jr.Violations = []Violation{}
	}
	b, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ShouldFail returns true only in preissuance mode when at least one violation
// matches a severity listed in the policy's fail_on list.
func (r *Report) ShouldFail(p *Policy, runMode string) bool {
	if runMode == "audit" {
		return false
	}
	for _, v := range r.Violations {
		for _, sev := range p.Enforcement.FailOn {
			if v.Severity == sev {
				return true
			}
		}
	}
	return false
}

// String returns a human-readable text report. Details (cert/CSR info) are
// printed first, followed by violations or a pass message.
func (r *Report) String() string {
	var sb strings.Builder
	if r.Details != "" {
		sb.WriteString(r.Details)
		sb.WriteString("\n")
	}
	if len(r.Violations) == 0 {
		sb.WriteString("No policy violations found.\n")
	} else {
		for _, v := range r.Violations {
			sb.WriteString(fmt.Sprintf("%s [%s]: %s (%s)\n", v.Severity, v.RuleID, v.Message, v.Standard))
		}
	}
	return sb.String()
}