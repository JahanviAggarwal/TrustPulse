package policy

import (
	"crypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"time"
)

func RuleMinRSAKeySize(cert *x509.Certificate) *Violation {
	if cert.PublicKeyAlgorithm == x509.RSA {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.Size()*8 < 2048 {
			return &Violation{
				RuleID:   "CABF-KEY-001",
				Standard: "CA/B Forum BR 6.1.5",
				Severity: SeverityHigh,
				Message:  "RSA key size is less than 2048 bits",
			}
		}
	}
	return nil
}

func RuleNoSHA1(cert *x509.Certificate) *Violation {
	if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
		cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {

		return &Violation{
			RuleID:   "CABF-SIG-001",
			Standard: "CA/B Forum BR 7.1.3",
			Severity: SeverityHigh,
			Message:  "SHA1 signature algorithm is not allowed",
		}
	}
	return nil
}

func RuleMaxValidity(cert *x509.Certificate) *Violation {
	maxDuration := 398 * 24 * time.Hour
	if cert.NotAfter.Sub(cert.NotBefore) > maxDuration {
		return &Violation{
			RuleID:   "CABF-VAL-001",
			Standard: "CA/B Forum BR 6.3.2",
			Severity: SeverityMedium,
			Message:  "Certificate validity exceeds 398 days",
		}
	}
	return nil
}

func RuleSANRequired(cert *x509.Certificate) *Violation {
	if len(cert.DNSNames) == 0 {
		return &Violation{
			RuleID:   "CABF-SAN-001",
			Standard: "CA/B Forum BR 7.1.4.2.1",
			Severity: SeverityHigh,
			Message:  "Subject Alternative Name extension is missing",
		}
	}
	return nil
}





