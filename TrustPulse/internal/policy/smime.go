package policy

import (
	"fmt"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

var OIDEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}

func RuleSMIMEEKU(cert *x509.Certificate) *Violation {

	if !IsSMIME(cert) {
		return nil
	}

	if !HasEKU(cert, x509.ExtKeyUsageEmailProtection) {
		return &Violation{
			RuleID:   "SMIME-EKU-MISSING",
			Severity: SeverityHigh,
			Message:  "S/MIME certificate missing emailProtection EKU",
			Standard: "CA/B Forum S/MIME BR",
		}
	}

	return nil
}

func RuleSMIMESAN(cert *x509.Certificate) *Violation {
	if !IsSMIME(cert) {
		return nil
	}

	if len(cert.EmailAddresses) == 0 {
		return &Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: SeverityHigh,
			Message:  "S/MIME certificate missing email in SAN or CN",
			Standard: "CA/B Forum S/MIME BR",
		}
	}

	return nil
}

func RuleSMIMERevocation(cert *x509.Certificate) *Violation {
	if !IsSMIME(cert) {
		return nil
	}

	if len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		return &Violation{
			RuleID:   "SMIME-REVOCATION-MISSING",
			Severity: SeverityMedium,
			Message:  "S/MIME certificate missing revocation information (OCSP/CRL)",
			Standard: "CA/B Forum S/MIME BR",
		}
	}

	return nil
}

func RuleSMIMEKeyUsage(cert *x509.Certificate) *Violation {

	if !IsSMIME(cert) {
		return nil
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &Violation{
			RuleID:   "SMIME-KEYUSAGE-INVALID",
			Severity: SeverityHigh,
			Message:  "S/MIME certificate missing digitalSignature key usage",
			Standard: "CA/B Forum S/MIME BR",
		}
	}

	return nil
}

// Keeping the IsSMIME function lightweight by only checking for the presence of the
// emailProtection EKU, which is a strong indicator of S/MIME usage.
// This avoids the need for more complex heuristics and keeps the function efficient.
func IsSMIME(cert *x509.Certificate) bool {
	// First check known EKUs
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageEmailProtection {
			fmt.Println("Matched ExtKeyUsageEmailProtection")
			return true
		}
	}

	// Then check unknown EKUs (for raw OIDs)
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}) {
			fmt.Println("Matched UnknownExtKeyUsage OID 1.3.6.1.5.5.7.3.4")
			return true
		}
	}

	return false
}

func HasEKU(cert *x509.Certificate, eku x509.ExtKeyUsage) bool {
	for _, v := range cert.ExtKeyUsage {
		if v == eku {
			return true
		}
	}
	return false
}
