package policy

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
)

func RuleRootSelfSigned(cert *x509.Certificate) *Violation {

	if !cert.IsCA {
		return nil
	}

	// Check signature verifies itself
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return &Violation{
			RuleID:   "ROOT-NOT-SELF-SIGNED",
			Severity: SeverityHigh,
			Message:  "Root CA certificate is not self-signed",
			Standard: "Root Program Policy",
		}
	}

	return nil
}

func RuleRootKeySize(cert *x509.Certificate) *Violation {

	if !cert.IsCA {
		return nil
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok && rsaKey.Size()*8 < 2048 {
		return &Violation{
			RuleID:   "ROOT-KEY-SIZE",
			Severity: SeverityHigh,
			Message:  "Root CA RSA key size less than 2048 bits",
			Standard: "Mozilla/Apple/Microsoft Root Policy",
		}
	}

	return nil
}

func RuleCAKeyUsage(cert *x509.Certificate) *Violation {
	if cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return &Violation{
				RuleID:   "RFC5280-CA-KEYUSAGE",
				Severity: SeverityHigh,
				Message:  "CA certificate does not have keyCertSign usage",
				Standard: "Custom RFC5280 CA Rule",
			}
		}
	}
	return nil
}
