package policy

import (
	"net"

	zcrypto "github.com/zmap/zcrypto/x509"
)

// TODO: Add valid values
const (
	OIDMLKEM512  = "2.16.840.1.101.3.4.4.1" // KYBER-512
	OIDMLKEM768  = "2.16.840.1.101.3.4.4.2" // KYBER-768
	OIDMLKEM1024 = "2.16.840.1.101.3.4.4.3" // KYBER-1024

	// Post-Quantum DSA (Dilithium) example OIDs
	OIDMLDSA44 = "1.3.6.1.4.1.99999.2.1" // placeholder OID for Dilithium-4
	OIDMLDSA65 = "1.3.6.1.4.1.99999.2.2" // placeholder OID for Dilithium-5
	OIDMLDSA87 = "1.3.6.1.4.1.99999.2.3" //
)

// ----------------------------------
// Rule: CN Matches SAN
// ----------------------------------
type RuleCNMatchesSAN struct{}

func (r *RuleCNMatchesSAN) ValidateCert(cert *zcrypto.Certificate) *Violation {

	if cert.Subject.CommonName == "" {
		return &Violation{
			RuleID:   "RFC5280-CN-SAN",
			Severity: SeverityHigh,
			Message:  "Certificate missing Subject Common Name",
			Standard: "Custom RFC5280 Alignment Check",
		}
	}

	match := false
	for _, san := range cert.DNSNames {
		if san == cert.Subject.CommonName {
			match = true
			break
		}
	}

	if !match {
		return &Violation{
			RuleID:   "RFC5280-CN-SAN",
			Severity: SeverityMedium,
			Message:  "Subject CN does not match any SAN",
			Standard: "Custom RFC5280 Alignment Check",
		}
	}

	return nil
}

func (r *RuleCNMatchesSAN) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {

	if csr.Subject.CommonName == "" {
		return &Violation{
			RuleID:   "RFC5280-CN-SAN",
			Severity: SeverityHigh,
			Message:  "CSR missing Subject Common Name",
			Standard: "Custom RFC5280 Alignment Check",
		}
	}

	match := false
	for _, san := range csr.DNSNames {
		if san == csr.Subject.CommonName {
			match = true
			break
		}
	}

	if !match {
		return &Violation{
			RuleID:   "RFC5280-CN-SAN",
			Severity: SeverityMedium,
			Message:  "CSR CN does not match any SAN",
			Standard: "Custom RFC5280 Alignment Check",
		}
	}

	return nil
}

// ----------------------------------
// Rule: Revocation Info
// ----------------------------------
type RuleRevocationInfo struct{}

func (r *RuleRevocationInfo) ValidateCert(cert *zcrypto.Certificate) *Violation {

	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		return &Violation{
			RuleID:   "RFC5280-REV-INFO",
			Severity: SeverityMedium,
			Message:  "Certificate missing CRL Distribution Points and OCSP URLs",
			Standard: "Custom RFC5280 Revocation Check",
		}
	}

	return nil
}

func (r *RuleRevocationInfo) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	// Revocation info not present in CSR
	return nil
}

// ----------------------------------
// Rule: PQC Key Size
// ----------------------------------
type RulePQCKeySize struct{}

func (r *RulePQCKeySize) ValidateCert(cert *zcrypto.Certificate) *Violation {

	algoOID := cert.PublicKeyAlgorithmOID.String()

	switch algoOID {

	case "2.16.840.1.101.3.4.1.55": // Kyber-512
		return &Violation{
			RuleID:   "RFC5280-PQC-KEM-512",
			Severity: SeverityMedium,
			Message:  "Certificate uses Kyber-512, consider higher security level",
			Standard: "NIST PQC (ML-KEM 512)",
		}

	case "2.16.840.1.101.3.4.1.56": // Kyber-768
		return nil

	case "2.16.840.1.101.3.4.1.57": // Kyber-1024
		return nil

	case "2.16.840.1.101.3.4.3.17", // Dilithium Cat 2
		"2.16.840.1.101.3.4.3.18", // Dilithium Cat 4
		"2.16.840.1.101.3.4.3.19": // Dilithium Cat 5
		return nil

	default:
		return nil
	}
}

func (r *RulePQCKeySize) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {
	// CSR may not expose algorithm OID cleanly in all cases
	return nil
}

// ----------------------------------
// Rule: Internal IP SAN Check
// ----------------------------------
type RuleInternalIPSAN struct{}

func (r *RuleInternalIPSAN) ValidateCert(cert *zcrypto.Certificate) *Violation {

	for _, ip := range cert.IPAddresses {

		// If public IP appears in internal cert → warn
		if ip.IsGlobalUnicast() && !isPrivateIP(ip) {
			return &Violation{
				RuleID:   "RFC5280-IP-SAN",
				Severity: SeverityMedium,
				Message:  "Internal certificate contains public IP SAN",
				Standard: "Custom RFC5280 Internal Network Check",
			}
		}
	}

	return nil
}

func (r *RuleInternalIPSAN) ValidateCSR(csr *zcrypto.CertificateRequest) *Violation {

	for _, ip := range csr.IPAddresses {
		if ip.IsGlobalUnicast() && !isPrivateIP(ip) {
			return &Violation{
				RuleID:   "RFC5280-IP-SAN",
				Severity: SeverityMedium,
				Message:  "CSR contains public IP SAN",
				Standard: "Custom RFC5280 Internal Network Check",
			}
		}
	}

	return nil
}

// Helper: Private IP Detection
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
