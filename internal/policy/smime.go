package policy

import (
	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	zcrypto "github.com/zmap/zcrypto/x509"
)

type RuleSMIME struct {
	Policy *models.SMIMEPolicy
}

func (r *RuleSMIME) ValidateCert(cert *zcrypto.Certificate, p *models.Policy) []*models.Violation {
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}

	if !IsSMIME(cert) {
		return nil
	}

	var violations []*models.Violation

	for _, requiredEKU := range r.Policy.RequireEKU {
		if !HasEKU(cert, requiredEKU) {
			violations = append(violations, &models.Violation{
				RuleID:   "SMIME-EKU-MISSING",
				Severity: models.SeverityHigh,
				Message:  "S/MIME certificate missing required EKU",
				Standard: "CA/B Forum S/MIME BR",
			})
		}
	}

	if r.Policy.RequireEmail && len(cert.EmailAddresses) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: models.SeverityHigh,
			Message:  "S/MIME certificate missing email in SAN or CN",
			Standard: "CA/B Forum S/MIME BR",
		})
	}

	if r.Policy.RequireDigitalSignature {
		if cert.KeyUsage == 0 {
			violations = append(violations, &models.Violation{
				RuleID:   "SMIME-KEYUSAGE-MISSING",
				Severity: models.SeverityHigh,
				Message:  "S/MIME certificate missing KeyUsage extension entirely",
				Standard: "CA/B Forum S/MIME BR",
			})
		} else if cert.KeyUsage&zcrypto.KeyUsageDigitalSignature == 0 {
			violations = append(violations, &models.Violation{
				RuleID:   "SMIME-KEYUSAGE-INVALID",
				Severity: models.SeverityHigh,
				Message:  "S/MIME certificate missing digitalSignature KeyUsage",
				Standard: "CA/B Forum S/MIME BR",
			})
		}
	}

	if r.Policy.RequireRevocation && len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "SMIME-REVOCATION-MISSING",
			Severity: models.SeverityMedium,
			Message:  "S/MIME certificate missing revocation information (OCSP/CRL)",
			Standard: "CA/B Forum S/MIME BR",
		})
	}

	return violations
}

func (r *RuleSMIME) ValidateCSR(csr *zcrypto.CertificateRequest, p *models.Policy) []*models.Violation {
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}

	var violations []*models.Violation

	if r.Policy.RequireEmail && len(csr.EmailAddresses) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: models.SeverityHigh,
			Message:  "S/MIME CSR missing email in SAN or CN",
			Standard: "Pre-issuance S/MIME policy",
		})
	}

	return violations
}

func IsSMIME(cert *zcrypto.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == zcrypto.ExtKeyUsageEmailProtection {
			return true
		}
	}

	return false
}

func HasEKU(cert *zcrypto.Certificate, eku zcrypto.ExtKeyUsage) bool {
	for _, v := range cert.ExtKeyUsage {
		if v == eku {
			return true
		}
	}

	return false
}