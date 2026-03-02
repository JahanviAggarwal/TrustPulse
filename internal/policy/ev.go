package policy

import (
	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	zcrypto "github.com/zmap/zcrypto/x509"
	zcryptopkix "github.com/zmap/zcrypto/x509/pkix"
)

// oidBusinessCategory is the X.500 attribute OID for businessCategory (2.5.4.15),
// as required by the CA/B Forum EV Guidelines Section 9.2.4.
// This is distinct from organizationalUnitName (2.5.4.11) — checking OU
// instead of businessCategory is a common but semantically incorrect shortcut.
//
// ObjectIdentifier is []int in both standard and zcrypto asn1 packages, so
// a plain slice literal is safe for direct comparison.
var oidBusinessCategory = []int{2, 5, 4, 15}

// hasBusinessCategory reports whether the given attribute list contains a
// businessCategory value (OID 2.5.4.15). It walks the raw Names slice rather
// than the named fields on pkix.Name, which does not expose businessCategory.
func hasBusinessCategory(names []zcryptopkix.AttributeTypeAndValue) bool {
	for _, attr := range names {
		if oidEqual(attr.Type, oidBusinessCategory) {
			return true
		}
	}
	return false
}

// oidEqual compares an asn1.ObjectIdentifier ([]int) against a plain []int.
func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------
// EV Rule Engine (Policy-driven)
// ------------------------
type RuleEV struct {
	Policy *models.EVPolicy
}

func (r *RuleEV) ValidateCert(cert *zcrypto.Certificate, p *models.Policy) []*models.Violation {
	if !p.EV.Enabled {
		return nil
	}

	if !IsEV(cert) {
		return nil
	}

	var violations []*models.Violation

	// Check required subject fields
	if p.EV.RequiredSubjectFields.Organization && len(cert.Subject.Organization) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: models.SeverityHigh,
			Message:  "EV certificate missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	// businessCategory is OID 2.5.4.15 — distinct from OU (2.5.4.11).
	// Walk Subject.Names to find the actual attribute rather than using
	// OrganizationalUnit which is a different field entirely.
	if p.EV.RequiredSubjectFields.BusinessCategory && !hasBusinessCategory(cert.Subject.Names) {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: models.SeverityMedium,
			Message:  "EV certificate missing businessCategory field (OID 2.5.4.15)",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	if p.EV.RequiredSubjectFields.Country && len(cert.Subject.Country) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: models.SeverityMedium,
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
			violations = append(violations, &models.Violation{
				RuleID:   "EV-EKU-MISSING",
				Severity: models.SeverityHigh,
				Message:  "EV certificate missing required EKU: " + ekuToString(requiredEKU),
				Standard: "CA/B Forum EV Guidelines",
			})
		}
	}

	return violations
}

func ekuToString(eku zcrypto.ExtKeyUsage) string {
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

func (r *RuleEV) ValidateCSR(csr *zcrypto.CertificateRequest, p *models.Policy) []*models.Violation {
	if !p.EV.Enabled {
		return nil
	}

	// EV CSR checks: only subject fields (cannot reliably check EKU)
	var violations []*models.Violation

	if p.EV.RequiredSubjectFields.Organization && len(csr.Subject.Organization) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: models.SeverityHigh,
			Message:  "EV CSR missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	// businessCategory is OID 2.5.4.15 — same check as for the cert path.
	if p.EV.RequiredSubjectFields.BusinessCategory && !hasBusinessCategory(csr.Subject.Names) {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: models.SeverityMedium,
			Message:  "EV CSR missing businessCategory field (OID 2.5.4.15)",
			Standard: "CA/B Forum EV Guidelines",
		})
	}

	if p.EV.RequiredSubjectFields.Country && len(csr.Subject.Country) == 0 {
		violations = append(violations, &models.Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: models.SeverityMedium,
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
