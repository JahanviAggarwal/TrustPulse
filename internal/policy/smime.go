package policy

import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

// ----------------------------
// Rule: S/MIME
// ----------------------------
type RuleSMIME struct {
	Policy *SMIMEPolicy
}

func (r *RuleSMIME) ValidateCert(cert *zcrypto.Certificate, p *Policy) []*Violation {
	// Guard nil policy before any field access, then skip non-S/MIME certs
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}
	if !IsSMIME(cert) {
		return nil
	}
	var violations []*Violation

	// 1️⃣ EKU Check
	for _, requiredEKU := range r.Policy.RequireEKU {
		if !HasEKU(cert, requiredEKU) {
			violations = append(violations, &Violation{
				RuleID:   "SMIME-EKU-MISSING",
				Severity: SeverityHigh,
				Message:  "S/MIME certificate missing required EKU",
				Standard: "CA/B Forum S/MIME BR",
			})
		}
	}

	// 2️⃣ Email SAN/CN check
	if r.Policy.RequireEmail && len(cert.EmailAddresses) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: SeverityHigh,
			Message:  "S/MIME certificate missing email in SAN or CN",
			Standard: "CA/B Forum S/MIME BR",
		})
	}

	// 3️⃣ DigitalSignature KeyUsage
	if r.Policy.RequireDigitalSignature {
		if cert.KeyUsage == 0 {
			violations = append(violations, &Violation{
				RuleID:   "SMIME-KEYUSAGE-MISSING",
				Severity: SeverityHigh,
				Message:  "S/MIME certificate missing KeyUsage extension entirely",
				Standard: "CA/B Forum S/MIME BR",
			})
		} else if cert.KeyUsage&zcrypto.KeyUsageDigitalSignature == 0 {
			violations = append(violations, &Violation{
				RuleID:   "SMIME-KEYUSAGE-INVALID",
				Severity: SeverityHigh,
				Message:  "S/MIME certificate missing digitalSignature KeyUsage",
				Standard: "CA/B Forum S/MIME BR",
			})
		}
	}

	// 4️⃣ Revocation info
	if r.Policy.RequireRevocation && len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "SMIME-REVOCATION-MISSING",
			Severity: SeverityMedium,
			Message:  "S/MIME certificate missing revocation information (OCSP/CRL)",
			Standard: "CA/B Forum S/MIME BR",
		})
	}

	return violations
}

func (r *RuleSMIME) ValidateCSR(csr *zcrypto.CertificateRequest, p *Policy) []*Violation {
	// Pre-issuance: guard nil policy first, then check enabled flag
	if r.Policy == nil || !r.Policy.Enabled {
		return nil
	}

	var violations []*Violation

	if r.Policy.RequireEmail && len(csr.EmailAddresses) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: SeverityHigh,
			Message:  "S/MIME CSR missing email in SAN or CN",
			Standard: "Pre-issuance S/MIME policy",
		})
	}

	return violations
}

// ----------------------------
// Helpers
// ----------------------------
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