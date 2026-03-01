package policy
import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

// ------------------------
// EV Rule Engine (Policy-driven)
// ------------------------
type RuleEV struct{
		Policy *EVPolicy
}

func (r *RuleEV) ValidateCert(cert *zcrypto.Certificate, p *Policy) []*Violation {
	if !p.EV.Enabled {
		return nil
	}

	if !IsEV(cert) {
		return nil
	}

	var violations []*Violation

	// Check required subject fields
	if p.EV.RequiredSubjectFields.Organization && len(cert.Subject.Organization) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: SeverityHigh,
			Message:  "EV certificate missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	if p.EV.RequiredSubjectFields.BusinessCategory && len(cert.Subject.OrganizationalUnit) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV certificate missing business category information",
			Standard: "CA/B Forum EV Guidelines",
		})
	}
	

	if p.EV.RequiredSubjectFields.Country && len(cert.Subject.Country) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV certificate missing Country field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	// Check required EKUs
	for _, requiredEKU := range p.EV.RequiredEKUs {
		found := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == requiredEKU {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, &Violation{
				RuleID:   "EV-EKU-MISSING",
				Severity: SeverityHigh,
				Message:  "EV certificate missing required EKU: " + EKUToString(requiredEKU),
				Standard: "CA/B Forum EV Guidelines",
			})
		}
	}

	return violations
}

func EKUToString(eku zcrypto.ExtKeyUsage) string {
	switch eku {
	case zcrypto.ExtKeyUsageServerAuth:
		return "serverAuth"
	case zcrypto.ExtKeyUsageClientAuth:
		return "clientAuth"
	case zcrypto.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case zcrypto.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case zcrypto.ExtKeyUsageTimeStamping:
		return "timeStamping"
	default:
		return "unknown"
	}
}

func (r *RuleEV) ValidateCSR(csr *zcrypto.CertificateRequest, p *Policy) []*Violation {
	if !p.EV.Enabled {
		return nil
	}

	// EV CSR checks: only subject fields (cannot reliably check EKU)
	var violations []*Violation

	if p.EV.RequiredSubjectFields.Organization && len(csr.Subject.Organization) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: SeverityHigh,
			Message:  "EV CSR missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	if p.EV.RequiredSubjectFields.BusinessCategory && len(csr.Subject.OrganizationalUnit) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV CSR missing business category information",
			Standard: "CA/B Forum EV Guidelines",
		})
	}
	

	if p.EV.RequiredSubjectFields.Country && len(csr.Subject.Country) == 0 {
		violations = append(violations, &Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV CSR missing Country field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	return violations
}

// ------------------------
// Helper: Is EV Certificate
// ------------------------
func IsEV(cert *zcrypto.Certificate) bool {
	for _, p := range cert.PolicyIdentifiers {
		if len(p) >= 5 &&
			p[0] == 2 && p[1] == 23 && p[2] == 140 &&
			p[3] == 1 && p[4] == 1 {
			return true
		}
	}
	return false
}
