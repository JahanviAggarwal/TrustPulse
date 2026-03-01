package policy

import (
	"crypto/rsa"

	zcrypto "github.com/zmap/zcrypto/x509"
)

// ----------------------------
// Root Certificate Rules
// ----------------------------
type RuleRoot struct {
	Policy *RootPolicy
}

func (r *RuleRoot) ValidateCert(cert *zcrypto.Certificate, p *Policy) []*Violation {
	if r.Policy == nil || !r.Policy.Enabled || !cert.IsCA {
		return nil
	}

	var violations []*Violation

	// Self-signed check
	if r.Policy.RequireSelfSigned {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			violations = append(violations, &Violation{
				RuleID:   "ROOT-NOT-SELF-SIGNED",
				Severity: SeverityHigh,
				Message:  "Root CA certificate is not self-signed",
				Standard: "Root Program Policy",
			})
		}
	}

	//  Minimum RSA key size
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.Size()*8 < r.Policy.MinRSAKeySize {
			violations = append(violations, &Violation{
				RuleID:   "ROOT-KEY-SIZE",
				Severity: SeverityHigh,
				Message:  "Root CA RSA key size below policy minimum",
				Standard: "Root Program Policy",
			})
		}
	}

	// KeyUsage check
	if r.Policy.RequireKeyUsageCertSign {
		if cert.KeyUsage&zcrypto.KeyUsageCertSign == 0 {
			violations = append(violations, &Violation{
				RuleID:   "RFC5280-CA-KEYUSAGE",
				Severity: SeverityHigh,
				Message:  "CA certificate missing keyCertSign usage",
				Standard: "RFC 5280 Section 4.2.1.3",
			})
		}
	}

	return violations
}

func (r *RuleRoot) ValidateCSR(csr *zcrypto.CertificateRequest, p *Policy) []*Violation {
	// Root CSR pre-issuance checks
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}

	var violations []*Violation

	// Example: enforce minimum RSA key size in pre-issuance CSR
	if rsaKey, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.Size()*8 < r.Policy.MinRSAKeySize {
			violations = append(violations, &Violation{
				RuleID:   "CSR-ROOT-KEY-001",
				Severity: SeverityHigh,
				Message:  "CSR RSA key size below root policy minimum",
				Standard: "Pre-issuance Root Policy",
			})
		}
	}

	return violations
}
