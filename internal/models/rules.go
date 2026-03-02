package models

import zcrypto "github.com/zmap/zcrypto/x509"

// Rule is the interface every policy check must implement.
// ValidateCert and ValidateCSR both receive the full Policy so rules can read
// any top-level setting (e.g. enforcement mode) alongside their own sub-policy.
type Rule interface {
	ValidateCert(cert *zcrypto.Certificate, p *Policy) []*Violation
	ValidateCSR(csr *zcrypto.CertificateRequest, p *Policy) []*Violation
}