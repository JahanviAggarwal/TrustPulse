package policy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
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

	// RSA key size
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

	// ECDSA minimum curve strength (P-192/P-224 are below modern baselines).
	// Set MinECDSACurveBits=0 to skip this check.
	// Note: zcrypto wraps ECDSA keys in *x509.AugmentedECDSA, so we handle both forms.
	if r.Policy.MinECDSACurveBits > 0 && cert.PublicKeyAlgorithm == x509.ECDSA {
		var curveBits int
		var curveName string

		switch pub := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			curveBits = pub.Params().BitSize
			curveName = pub.Params().Name
		case *x509.AugmentedECDSA:
			curveBits = pub.Pub.Params().BitSize
			curveName = pub.Pub.Params().Name
		}

		if curveBits > 0 && curveBits < r.Policy.MinECDSACurveBits {
			violations = append(violations, &Violation{
				RuleID:   "CERT-ECDSA-CURVE-001",
				Standard: "Certificate Policy",
				Severity: SeverityHigh,
				Message: fmt.Sprintf(
					"ECDSA curve %s (%d bits) is below policy minimum of %d bits",
					curveName, curveBits, r.Policy.MinECDSACurveBits,
				),
			})
		}
	}

	// Signature algorithm allow-list
	if len(r.Policy.AllowedSignatureAlgorithms) > 0 {
		sig := cert.SignatureAlgorithm.String()
		allowed := false
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

	// Maximum validity period
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

	// SAN presence
	if r.Policy.RequireSAN {
		if len(cert.DNSNames) == 0 && len(cert.EmailAddresses) == 0 && len(cert.IPAddresses) == 0 {
			violations = append(violations, &Violation{
				RuleID:   "CERT-SAN-001",
				Standard: "Certificate Policy",
				Severity: SeverityHigh,
				Message:  "Subject Alternative Name extension is required",
			})
		}
	}

	// PQC algorithm checks — skip for standard RSA/ECDSA/Ed* algorithms to
	// avoid false positives on every normal certificate.
	if r.Policy.EnablePQCChecks {
		algoOID := cert.PublicKeyAlgorithmOID.String()
		if !isClassicalAlgoOID(algoOID) {
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
			// ML-KEM-512 (Kyber-512) is the lowest NIST PQC security level
			if algoOID == "2.16.840.1.101.3.4.1.55" && r.Policy.DisallowLowSecurityPQC {
				violations = append(violations, &Violation{
					RuleID:   "RFC5280-PQC-LOW-SECURITY",
					Severity: SeverityMedium,
					Message:  "Certificate uses ML-KEM-512 (lower security level)",
					Standard: "NIST PQC",
				})
			}
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

	if csr.PublicKeyAlgorithm == x509.RSA {
		if key, ok := csr.PublicKey.(*rsa.PublicKey); ok {
			if key.Size()*8 < r.Policy.MinRSAKeySize {
				violations = append(violations, &Violation{
					RuleID:   "CSR-KEY-001",
					Standard: "Pre-issuance guardrail",
					Severity: SeverityHigh,
					Message:  "CSR RSA key size below minimum requirement",
				})
			}
		}
	}

	if len(r.Policy.AllowedSignatureAlgorithms) > 0 {
		sig := csr.SignatureAlgorithm.String()
		allowed := false
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

	if r.Policy.RequireSAN {
		if len(csr.DNSNames) == 0 && len(csr.EmailAddresses) == 0 && len(csr.IPAddresses) == 0 {
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

	if r.Policy.RequireSAN {
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
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
		if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
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

// isClassicalAlgoOID returns true for standard RSA/ECDSA/EdDSA OIDs.
// PQC allowlist/denylist checks are skipped for these to avoid false positives.
func isClassicalAlgoOID(oid string) bool {
	switch oid {
	case "1.2.840.113549.1.1.1", // rsaEncryption
		"1.2.840.10045.2.1",     // id-ecPublicKey
		"1.3.101.112",           // id-Ed25519
		"1.3.101.113",           // id-Ed448
		"1.2.840.113549.1.1.5",  // sha1WithRSAEncryption
		"1.2.840.113549.1.1.11", // sha256WithRSAEncryption
		"1.2.840.113549.1.1.12", // sha384WithRSAEncryption
		"1.2.840.113549.1.1.13": // sha512WithRSAEncryption
		return true
	}
	return false
}