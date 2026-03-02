package models

import zcrypto "github.com/zmap/zcrypto/x509"

// Rule is the interface all policy checks implement.
type Rule interface {
	ValidateCert(cert *zcrypto.Certificate, p *Policy) []*Violation
	ValidateCSR(csr *zcrypto.CertificateRequest, p *Policy) []*Violation
}