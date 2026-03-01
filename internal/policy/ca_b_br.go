package policy

import (
	"crypto/rsa"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"
)

type RuleTLSServerCert struct {
	Policy *TLSServerPolicy
}

type RuleUniversalCert struct {
	Policy *CertificatePolicy
}

type RuleUniversalCSR struct {
	Policy *CSRPolicy
}
func (r *RuleUniversalCert) ValidateCert(cert *x509.Certificate, p *Policy) []*Violation {
	if r.Policy == nil {
		return nil
	}

	var violations []*Violation

	// 1️⃣ Minimum RSA key size
	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if rsaKey.Size()*8 < r.Policy.MinRSAKeySize {
				violations = append(violations, &Violation{
					RuleID:   "CERT-KEY-001",
					Standard: "Certificate Policy",
					Severity: SeverityHigh,
					Message:  "RSA key size below minimum requirement",
				})
			}
		}
	}

	// 2️⃣ Allowed signature algorithms
	if len(r.Policy.AllowedSignatureAlgorithms) > 0 {
		allowed := false
		sig := cert.SignatureAlgorithm.String()
		for _, a := range r.Policy.AllowedSignatureAlgorithms {
			if strings.EqualFold(a, sig) {
				allowed = true
				break
			}
		}

		if !allowed {
			violations = append(violations, &Violation{
				RuleID:   "CERT-SIG-001",
				Standard: "Certificate Policy",
				Severity: SeverityHigh,
				Message:  "Signature algorithm not allowed by policy",
			})
		}
	}

	// 3️⃣ Maximum validity
	if r.Policy.MaxValidityDays > 0 {
		maxDuration := time.Duration(r.Policy.MaxValidityDays) * 24 * time.Hour
		if cert.NotAfter.Sub(cert.NotBefore) > maxDuration {
			violations = append(violations, &Violation{
				RuleID:   "CERT-VAL-001",
				Standard: "Certificate Policy",
				Severity: SeverityMedium,
				Message:  "Certificate validity exceeds policy maximum",
			})
		}
	}

	// 4️⃣ SAN required (generic, if enabled)
	if r.Policy.RequireSAN {
		if len(cert.DNSNames) == 0 &&
			len(cert.EmailAddresses) == 0 &&
			len(cert.IPAddresses) == 0 {
			violations = append(violations, &Violation{
				RuleID:   "CERT-SAN-001",
				Standard: "Certificate Policy",
				Severity: SeverityHigh,
				Message:  "Subject Alternative Name extension is required",
			})
		}
	}

	// 5️⃣ PQC checks (if enabled)
	if r.Policy.EnablePQCChecks {
		algoOID := cert.PublicKeyAlgorithmOID.String()

		// Check allowlist
		if len(r.Policy.AllowedPQCOIDs) > 0 {
			allowed := false
			for _, oid := range r.Policy.AllowedPQCOIDs {
				if algoOID == oid {
					allowed = true
					break
				}
			}
			if !allowed {
				violations = append(violations, &Violation{
					RuleID:   "RFC5280-PQC-NOT-ALLOWED",
					Severity: SeverityHigh,
					Message:  "Certificate uses disallowed PQC algorithm OID: " + algoOID,
					Standard: "RFC5280 / NIST PQC",
				})
			}
		}

		// Example downgrade warning for Kyber-512
		if algoOID == "2.16.840.1.101.3.4.1.55" && r.Policy.DisallowLowSecurityPQC {
			violations = append(violations, &Violation{
				RuleID:   "RFC5280-PQC-LOW-SECURITY",
				Severity: SeverityMedium,
				Message:  "Certificate uses ML-KEM-512 (lower security level)",
				Standard: "NIST PQC",
			})
		}
	}

	return violations
}

func (r *RuleUniversalCert) ValidateCSR(csr *x509.CertificateRequest, p *Policy) []*Violation {
	return nil
}

func (r *RuleUniversalCSR) ValidateCSR(csr *x509.CertificateRequest, p *Policy) []*Violation {
	if r.Policy == nil {
		return nil
	}

	var violations []*Violation

	// 1️⃣ Minimum RSA key size
	if csr.PublicKeyAlgorithm == x509.RSA {
		key := csr.PublicKey.(*rsa.PublicKey)
		if key.Size()*8 < r.Policy.MinRSAKeySize {
			violations = append(violations, &Violation{
				RuleID:   "CSR-KEY-001",
				Standard: "Pre-issuance guardrail",
				Severity: SeverityHigh,
				Message:  "CSR RSA key size below minimum requirement",
			})
		}
	}

	// 2️⃣ Allowed signature algorithms
	if len(r.Policy.AllowedSignatureAlgorithms) > 0 {
		allowed := false
		sig := csr.SignatureAlgorithm.String()

		for _, a := range r.Policy.AllowedSignatureAlgorithms {
			if strings.EqualFold(a, sig) {
				allowed = true
				break
			}
		}

		if !allowed {
			violations = append(violations, &Violation{
				RuleID:   "CSR-SIG-001",
				Standard: "Pre-issuance guardrail",
				Severity: SeverityHigh,
				Message:  "CSR signature algorithm not allowed by policy",
			})
		}
	}

	// 3️⃣ SAN required (generic)
	if r.Policy.RequireSAN {
		if len(csr.DNSNames) == 0 &&
			len(csr.EmailAddresses) == 0 &&
			len(csr.IPAddresses) == 0 {

			violations = append(violations, &Violation{
				RuleID:   "CSR-SAN-001",
				Standard: "Pre-issuance guardrail",
				Severity: SeverityHigh,
				Message:  "CSR missing Subject Alternative Name extension",
			})
		}
	}

	return violations
}

func (r *RuleUniversalCSR) ValidateCert(cert *x509.Certificate, p *Policy) []*Violation {
	return nil
}

func (r *RuleTLSServerCert) ValidateCert(cert *x509.Certificate, p *Policy) []*Violation {
	if r.Policy == nil {
		return nil
	}

	var violations []*Violation
	// 1️⃣ SAN required for TLS
	if r.Policy.RequireSAN {
		if len(cert.DNSNames) == 0 &&
			len(cert.IPAddresses) == 0 {

			violations = append(violations, &Violation{
				RuleID:   "TLS-SAN-001",
				Standard: "CA/B Forum BR 7.1.4.2.1",
				Severity: SeverityHigh,
				Message:  "TLS certificate must contain DNS or IP SAN",
			})
		}
	}

	return violations
}

func (r *RuleTLSServerCert) ValidateCSR(csr *x509.CertificateRequest, p *Policy) []*Violation {
	if r.Policy == nil {
		return nil
	}

	var violations []*Violation

	if r.Policy.RequireSAN {
		if len(csr.DNSNames) == 0 &&
			len(csr.IPAddresses) == 0 {

			violations = append(violations, &Violation{
				RuleID:   "TLS-CSR-SAN-001",
				Standard: "Pre-issuance TLS policy",
				Severity: SeverityHigh,
				Message:  "TLS CSR must contain DNS or IP SAN",
			})
		}
	}

	return violations
}
