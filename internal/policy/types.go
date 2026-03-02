package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
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

// Summary provides aggregate counts across all violations in a Report.
type Summary struct {
	Total  int  `json:"total"`
	High   int  `json:"high"`
	Medium int  `json:"medium"`
	Low    int  `json:"low"`
	Passed bool `json:"passed"`
}

// jsonReport is the serialisable form of a Report (excludes raw cert/CSR details).
type jsonReport struct {
	Summary    Summary     `json:"summary"`
	Violations []Violation `json:"violations"`
}

type Report struct {
	Violations []Violation
	Details    string // store raw certificate/CSR details
}

type Rule interface {
	ValidateCert(cert *x509.Certificate, p *Policy) []*Violation
	ValidateCSR(csr *x509.CertificateRequest, p *Policy) []*Violation
}

// BuildSummary computes violation counts and sets Passed based on policy
// enforcement rules. Call this before JSON() or after all violations are known.
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

// JSON returns an indented JSON representation of the report, including a
// summary of violation counts. It never includes raw PEM/cert detail text.
func (r *Report) JSON(p *Policy, runMode string) (string, error) {
	jr := jsonReport{
		Summary:    r.BuildSummary(p, runMode),
		Violations: r.Violations,
	}
	if jr.Violations == nil {
		jr.Violations = []Violation{} // ensure "violations": [] not null
	}
	b, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

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

// String returns a human-readable text representation of the report.
func (r *Report) String() string {
	var sb strings.Builder

	// Print raw details first
	if r.Details != "" {
		sb.WriteString(r.Details)
		sb.WriteString("\n")
	}

	// Print violations
	if len(r.Violations) == 0 {
		sb.WriteString("✅ No policy violations found.\n")
	} else {
		for _, v := range r.Violations {
			sb.WriteString(fmt.Sprintf("%s [%s]: %s (%s)\n", v.Severity, v.RuleID, v.Message, v.Standard))
		}
	}

	return sb.String()
}