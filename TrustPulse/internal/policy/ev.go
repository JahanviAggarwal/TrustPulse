package policy

import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

// ------------------------
// Rule: EV Organization Present
// ------------------------
type RuleEVOrganizationPresent struct{}

func (r *RuleEVOrganizationPresent) ValidateCert(cert *zcrypto.Certificate) *Violation {
	if !IsEV(cert) {
		return nil
	}

	if len(cert.Subject.Organization) == 0 {
		return &Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: SeverityHigh,
			Message:  "EV certificate missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

func (r *RuleEVOrganizationPresent) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	// CSR may not have EV policy identifiers yet
	// Skip or optionally check if Organization field is present
	if len(csr.Subject.Organization) == 0 {
		return &Violation{
			RuleID:   "EV-ORG-MISSING",
			Severity: SeverityHigh,
			Message:  "EV CSR missing Organization field",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

// ------------------------
// Rule: EV Business Category
// ------------------------
type RuleEVBusinessCategory struct{}

func (r *RuleEVBusinessCategory) ValidateCert(cert *zcrypto.Certificate) *Violation {
	if !IsEV(cert) {
		return nil
	}

	if len(cert.Subject.OrganizationalUnit) == 0 {
		return &Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV certificate missing business category information",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

func (r *RuleEVBusinessCategory) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	if len(csr.Subject.OrganizationalUnit) == 0 {
		return &Violation{
			RuleID:   "EV-BUSINESS-CATEGORY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV CSR missing business category information",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

// ------------------------
// Rule: EV Country Present
// ------------------------
type RuleEVCountryPresent struct{}

func (r *RuleEVCountryPresent) ValidateCert(cert *zcrypto.Certificate) *Violation {
	if !IsEV(cert) {
		return nil
	}

	if len(cert.Subject.Country) == 0 {
		return &Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV certificate missing Country field",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

func (r *RuleEVCountryPresent) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	if len(csr.Subject.Country) == 0 {
		return &Violation{
			RuleID:   "EV-COUNTRY-MISSING",
			Severity: SeverityMedium,
			Message:  "EV CSR missing Country field",
			Standard: "CA/B Forum EV Guidelines",
		}
	}
	return nil
}

// ------------------------
// Rule: EV Must Be TLS Server
// ------------------------
type RuleEVMustBeTLS struct{}

func (r *RuleEVMustBeTLS) ValidateCert(cert *zcrypto.Certificate) *Violation {
	if !IsEV(cert) {
		return nil
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == zcrypto.ExtKeyUsageServerAuth {
			return nil
		}
	}

	return &Violation{
		RuleID:   "EV-NON-TLS",
		Severity: SeverityHigh,
		Message:  "EV certificate must include TLS serverAuth EKU",
		Standard: "CA/B Forum EV Guidelines",
	}
}

func (r *RuleEVMustBeTLS) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	// Cannot reliably check EKU in CSR
    // Skip pre-issuance check
    return nil
}

// ------------------------
// Helpers
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

func IsTLSServer(cert *zcrypto.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == zcrypto.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}
