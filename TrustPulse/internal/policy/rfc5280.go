package policy

import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

const (
	OIDMLKEM512  = "2.16.840.1.101.3.4.4.1" // KYBER-512
	OIDMLKEM768  = "2.16.840.1.101.3.4.4.2" // KYBER-768
	OIDMLKEM1024 = "2.16.840.1.101.3.4.4.3" // KYBER-1024

	 // Post-Quantum DSA (Dilithium) example OIDs
    OIDMLDSA44 = "1.3.6.1.4.1.99999.2.1" // placeholder OID for Dilithium-4
    OIDMLDSA65 = "1.3.6.1.4.1.99999.2.2" // placeholder OID for Dilithium-5
    OIDMLDSA87 = "1.3.6.1.4.1.99999.2.3" //
)

func RuleCNMatchesSAN(cert *zcrypto.Certificate) *Violation {
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


// 3️⃣ Certificate must have CRL Distribution Points or OCSP URL
func RuleRevocationInfo(cert *zcrypto.Certificate) *Violation {
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

// 4️⃣ PQC Key Size check (example for ML-KEM / Dilithium)
func RulePQCKeySize(cert *zcrypto.Certificate) *Violation {
	// Get the algorithm OID from the public key
	algoOID := cert.PublicKeyAlgorithmOID.String()

	switch algoOID {
	case "2.16.840.1.101.3.4.1.55": // Kyber-512
		return &Violation{
			RuleID:   "RFC5280-PQC-KEM-512",
			Severity: SeverityMedium,
			Message:  "Certificate uses Kyber-512, consider using higher security level",
			Standard: "NIST PQC (ML-KEM 512)",
		}

	case "2.16.840.1.101.3.4.1.56": // Kyber-768
		// Kyber-768 is a stronger variant — may pass or warn
		return nil

	case "2.16.840.1.101.3.4.1.57": // Kyber-1024
		// Kyber-1024 is the highest level — no warning
		return nil

	case "2.16.840.1.101.3.4.3.17", // Dilithium Cat 2
		"2.16.840.1.101.3.4.3.18", // Dilithium Cat 4
		"2.16.840.1.101.3.4.3.19": // Dilithium Cat 5
		// Accept PQC signature key — optional additional checks here
		return nil

	default:
		// Not a recognized PQC OID
		return nil
	}
}

// 5️⃣ Optional: Internal IP SAN validation
func RuleInternalIPSAN(cert *zcrypto.Certificate) *Violation {
	for _, ip := range cert.IPAddresses {
		if ip.IsGlobalUnicast() {
			return &Violation{
				RuleID:   "RFC5280-IP-SAN",
				Severity: SeverityMedium,
				Message:  "Internal cert contains public IP SAN",
				Standard: "Custom RFC5280 Internal Network Check",
			}
		}
	}
	return nil
}