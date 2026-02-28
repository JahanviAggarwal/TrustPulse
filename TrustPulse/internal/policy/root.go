package policy

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
)

// ----------------------
// Rule: Root Self-Signed
// ----------------------
type RuleRootSelfSigned struct{}

func (r *RuleRootSelfSigned) ValidateCert(cert *x509.Certificate) *Violation {

	if !cert.IsCA {
		return nil
	}

	// Verify certificate is self-signed
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return &Violation{
			RuleID:   "ROOT-NOT-SELF-SIGNED",
			Severity: SeverityHigh,
			Message:  "Root CA certificate is not self-signed",
			Standard: "Root Program Policy",
		}
	}

	return nil
}

func (r *RuleRootSelfSigned) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// CSR cannot be self-signed root certificate
	return nil
}

// ----------------------
// Rule: Root Key Size
// ----------------------
type RuleRootKeySize struct{}

func (r *RuleRootKeySize) ValidateCert(cert *x509.Certificate) *Violation {

	if !cert.IsCA {
		return nil
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok && rsaKey.Size()*8 < 2048 {
		return &Violation{
			RuleID:   "ROOT-KEY-SIZE",
			Severity: SeverityHigh,
			Message:  "Root CA RSA key size less than 2048 bits",
			Standard: "Mozilla/Apple/Microsoft Root Policy",
		}
	}

	return nil
}

func (r *RuleRootKeySize) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// Root key size is enforced after issuance
	return nil
}

// ----------------------
// Rule: CA Key Usage
// ----------------------
type RuleCAKeyUsage struct{}

func (r *RuleCAKeyUsage) ValidateCert(cert *x509.Certificate) *Violation {

	if cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return &Violation{
				RuleID:   "RFC5280-CA-KEYUSAGE",
				Severity: SeverityHigh,
				Message:  "CA certificate does not have keyCertSign usage",
				Standard: "RFC 5280 Section 4.2.1.3",
			}
		}
	}

	return nil
}

func (r *RuleCAKeyUsage) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// KeyUsage extension not reliably available in CSR
	return nil
}
