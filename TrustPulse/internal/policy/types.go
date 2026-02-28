package policy

import "github.com/zmap/zcrypto/x509"

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
	RuleID      string   `json:"rule_id"`
	Standard    string   `json:"standard"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
}

// type Rule func(cert *x509.Certificate) *Violation

type Rule interface {
    ValidateCert(cert *x509.Certificate) *Violation
    ValidateCSR(csr *x509.CertificateRequest) *Violation
}