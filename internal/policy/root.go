package policy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// ----------------------------
// Root Certificate Rules
// ----------------------------
type RuleRoot struct {
	Policy *models.RootPolicy
}

func (r *RuleRoot) ValidateCert(cert *zcrypto.Certificate, p *models.Policy) []*models.Violation {
	if r.Policy == nil || !r.Policy.Enabled || !cert.IsCA {
		return nil
	}

	var violations []*models.Violation

	// Self-signed check
	if r.Policy.RequireSelfSigned {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			violations = append(violations, &models.Violation{
				RuleID:   "ROOT-NOT-SELF-SIGNED",
				Severity: models.SeverityHigh,
				Message:  "Root CA certificate is not self-signed",
				Standard: "Root Program Policy",
			})
		}
	}

	// Minimum RSA key size
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.Size()*8 < r.Policy.MinRSAKeySize {
			violations = append(violations, &models.Violation{
				RuleID:   "ROOT-KEY-SIZE",
				Severity: models.SeverityHigh,
				Message:  "Root CA RSA key size below policy minimum",
				Standard: "Root Program Policy",
			})
		}
	}

	// Minimum ECDSA curve strength for root CA (0 = disabled).
	if r.Policy.MinECDSACurveBits > 0 && cert.PublicKeyAlgorithm == zcrypto.ECDSA {
		var (
			curveBits int
			curveName string
		)

		switch pub := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			curveBits = pub.Params().BitSize
			curveName = pub.Params().Name
		case *zcrypto.AugmentedECDSA:
			curveBits = pub.Pub.Params().BitSize
			curveName = pub.Pub.Params().Name
		}

		if curveBits > 0 && curveBits < r.Policy.MinECDSACurveBits {
			violations = append(violations, &models.Violation{
				RuleID:   "ROOT-ECDSA-CURVE",
				Severity: models.SeverityHigh,
				Message: fmt.Sprintf(
					"Root CA ECDSA curve %s (%d bits) is below policy minimum of %d bits",
					curveName, curveBits, r.Policy.MinECDSACurveBits,
				),
				Standard: "Root Program Policy",
			})
		}
	}

	// KeyUsage check
	if r.Policy.RequireKeyUsageCertSign {
		if cert.KeyUsage&zcrypto.KeyUsageCertSign == 0 {
			violations = append(violations, &models.Violation{
				RuleID:   "RFC5280-CA-KEYUSAGE",
				Severity: models.SeverityHigh,
				Message:  "CA certificate missing keyCertSign usage",
				Standard: "RFC 5280 Section 4.2.1.3",
			})
		}
	}

	return violations
}

func (r *RuleRoot) ValidateCSR(csr *zcrypto.CertificateRequest, p *models.Policy) []*models.Violation {
	// Root CSR pre-issuance checks
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}

	var violations []*models.Violation

	// Example: enforce minimum RSA key size in pre-issuance CSR
	if rsaKey, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.Size()*8 < r.Policy.MinRSAKeySize {
			violations = append(violations, &models.Violation{
				RuleID:   "CSR-ROOT-KEY-001",
				Severity: models.SeverityHigh,
				Message:  "CSR RSA key size below root policy minimum",
				Standard: "Pre-issuance Root Policy",
			})
		}
	}

	return violations
}
