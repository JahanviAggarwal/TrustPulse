package policy

import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

func RuleEVOrganizationPresent(cert *zcrypto.Certificate) *Violation {

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

func RuleEVBusinessCategory(cert *zcrypto.Certificate) *Violation {

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

func RuleEVCountryPresent(cert *zcrypto.Certificate) *Violation {

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

func RuleEVMustBeTLS(cert *zcrypto.Certificate) *Violation {

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
		Message:  "EV policy present but certificate is not TLS serverAuth",
		Standard: "CA/B Forum EV Guidelines",
	}
}

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
