package policy

import (
	"crypto/rsa"
	"time"

	"github.com/zmap/zcrypto/x509"
)

type RuleMinRSAKeySize struct{}
type RuleNoSHA1 struct{}
type RuleMaxValidity struct{}
type RuleSANRequired struct{}

func (r RuleMinRSAKeySize) ValidateCert(cert *x509.Certificate) *Violation {
	if cert.PublicKeyAlgorithm == x509.RSA {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.Size()*8 < 2048 {
			return &Violation{
				RuleID:   "CABF-KEY-001",
				Standard: "CA/B Forum BR 6.1.5",
				Severity: SeverityHigh,
				Message:  "RSA key size is less than 2048 bits",
			}
		}
	}
	return nil
}

func (r RuleMinRSAKeySize) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	if csr.PublicKeyAlgorithm == x509.RSA {
		key := csr.PublicKey.(*rsa.PublicKey)
		if key.Size()*8 < 2048 {
			return &Violation{
				RuleID:   "CSR-KEY-001",
				Standard: "Pre-issuance guardrail: RSA key < 2048",
				Severity: SeverityHigh,
				Message:  "CSR RSA key size is less than 2048 bits",
			}
		}
	}
	return nil
}

func (r RuleNoSHA1) ValidateCert(cert *x509.Certificate) *Violation {
	if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
		cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {

		return &Violation{
			RuleID:   "CABF-SIG-001",
			Standard: "CA/B Forum BR 7.1.3",
			Severity: SeverityHigh,
			Message:  "SHA1 signature algorithm is not allowed for issued certificates",
		}
	}
	return nil
}

// ValidateCSR checks a pre-issuance CSR
func (r RuleNoSHA1) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	if csr.SignatureAlgorithm == x509.SHA1WithRSA ||
		csr.SignatureAlgorithm == x509.DSAWithSHA1 ||
		csr.SignatureAlgorithm == x509.ECDSAWithSHA1 {

		return &Violation{
			RuleID:   "CSR-SIG-001",
			Standard: "Pre-issuance guardrail: CA/B Forum BR 7.1.3",
			Severity: SeverityHigh,
			Message:  "SHA1 signature algorithm is not allowed in CSR",
		}
	}
	return nil
}

func (r RuleMaxValidity) ValidateCert(cert *x509.Certificate) *Violation {
	maxDuration := 398 * 24 * time.Hour
	if cert.NotAfter.Sub(cert.NotBefore) > maxDuration {
		return &Violation{
			RuleID:   "CABF-VAL-001",
			Standard: "CA/B Forum BR 6.3.2",
			Severity: SeverityMedium,
			Message:  "Certificate validity exceeds 398 days",
		}
	}
	return nil
}

func (r RuleMaxValidity) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	return nil
}

func (r RuleSANRequired) ValidateCert(cert *x509.Certificate) *Violation {
	if len(cert.DNSNames) == 0 && len(cert.EmailAddresses) == 0 && len(cert.IPAddresses) == 0 {
		return &Violation{
			RuleID:   "CABF-SAN-001",
			Standard: "CA/B Forum BR 7.1.4.2.1",
			Severity: SeverityHigh,
			Message:  "Subject Alternative Name extension is missing",
		}
	}
	return nil
}

func (r RuleSANRequired) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	if len(csr.DNSNames) == 0 && len(csr.EmailAddresses) == 0 && len(csr.IPAddresses) == 0 {
		return &Violation{
			RuleID:   "CSR-SAN-001",
			Standard: "CA/B Forum BR 7.1.4.2.1",
			Severity: SeverityHigh,
			Message:  "CSR missing Subject Alternative Name extension",
		}
	}
	return nil
}
