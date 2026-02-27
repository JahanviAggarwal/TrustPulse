package policy

import "github.com/zmap/zcrypto/x509"

type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Violation struct {
	RuleID      string   `json:"rule_id"`
	Standard    string   `json:"standard"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
}

type Rule func(cert *x509.Certificate) *Violation