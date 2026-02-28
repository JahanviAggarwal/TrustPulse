package policy

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

var OIDEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}

// RuleSMIMEEKU checks that a certificate has emailProtection EKU.
// CSR validation is skipped (cannot reliably check EKU in CSR)
type RuleSMIMEEKU struct{}

func (r *RuleSMIMEEKU) ValidateCert(cert *x509.Certificate) *Violation {
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

func (r *RuleSMIMEEKU) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// CSRs do not reliably expose EKU; skip check
	return nil
}

// RuleSMIMESAN checks for email address in SAN or CN
type RuleSMIMESAN struct{}

func (r *RuleSMIMESAN) ValidateCert(cert *x509.Certificate) *Violation {
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

func (r *RuleSMIMESAN) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// Check CSR Subject for email as pre-issuance guardrail
	if len(csr.EmailAddresses) == 0 {
		return &Violation{
			RuleID:   "SMIME-SAN-MISSING",
			Severity: SeverityHigh,
			Message:  "S/MIME CSR missing email in SAN or CN",
			Standard: "CA/B Forum S/MIME BR",
		}
	}
	return nil
}

// RuleSMIMERevocation checks that revocation info exists in certificate
type RuleSMIMERevocation struct{}

func (r *RuleSMIMERevocation) ValidateCert(cert *x509.Certificate) *Violation {
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

func (r *RuleSMIMERevocation) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// Cannot check revocation info in CSR; skip
	return nil
}

// RuleSMIMEKeyUsage checks digitalSignature KeyUsage
type RuleSMIMEKeyUsage struct{}

func (r *RuleSMIMEKeyUsage) ValidateCert(cert *x509.Certificate) *Violation {
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

func (r *RuleSMIMEKeyUsage) ValidateCSR(csr *x509.CertificateRequest) *Violation {
	// Cannot check KeyUsage in CSR; skip
	return nil
}

// -------------------- Helper Functions --------------------

// IsSMIME checks if a certificate is intended for S/MIME
// Keeping the IsSMIME function lightweight by only checking for the presence of the
// emailProtection EKU, which is a strong indicator of S/MIME usage.
// This avoids the need for more complex heuristics and keeps the function efficient.
func IsSMIME(cert *x509.Certificate) bool {
	// First check known EKUs
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageEmailProtection {
			return true
		}
	}

	// Then check unknown EKUs (for raw OIDs)
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}) {
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
