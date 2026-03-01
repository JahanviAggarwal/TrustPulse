package policy

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

type Severity string
type TargetKind int

const (
	KindCertificate TargetKind = iota
	KindCSR
)

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Target struct {
	Kind TargetKind
	Cert *x509.Certificate
	CSR  *x509.CertificateRequest
}

type Violation struct {
	RuleID   string   `json:"rule_id"`
	Standard string   `json:"standard"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

type Report struct {
	Violations []Violation
	Details    string // store raw certificate/CSR details
}

type Rule interface {
	ValidateCert(cert *x509.Certificate, p *Policy) []*Violation
	ValidateCSR(csr *x509.CertificateRequest, p *Policy) []*Violation
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

// Pretty-print the report for CLI output
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
			// icon := "⚠️"
			// if v.Severity == SeverityHigh {
			// 	icon = "❌"
			// }
			sb.WriteString(fmt.Sprintf("%s [%s]: %s (%s)\n", v.Severity, v.RuleID, v.Message, v.Standard))
		}
	}

	return sb.String()
}
