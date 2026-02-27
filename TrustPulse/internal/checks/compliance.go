package checks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/zmap/zcrypto/x509"
)

func GetCertificateDetails(cert *x509.Certificate) string {
	// 1. Validity
	validity := fmt.Sprintf("Validity: %s -> %s\n",
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
	)

	// 2. Key Type & Key Size (derive from PublicKey)
	keySize := ""
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = fmt.Sprintf("Key Type: RSA, Key Size: %d bits\n", pub.N.BitLen())
	case *ecdsa.PublicKey:
		keySize = fmt.Sprintf("Key Type: ECDSA, Key Size: %d bits\n", pub.Params().BitSize)
	case ed25519.PublicKey:
		keySize = fmt.Sprintf("Key Type: Ed25519, Key Size: %d bits\n", len(pub)*8)
	default:
		keySize = fmt.Sprintf("Key Type: Unknown (%T)\n", pub)
	}

	// 3. Signature Algorithm
	sigAlgo := fmt.Sprintf("Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())

	// 4. Subject Alternative Names
	san := "SANs: "
	if len(cert.DNSNames) > 0 {
		san += fmt.Sprintf("%v", cert.DNSNames)
	} else {
		san += "None"
	}

	// 5. Assemble details
	return validity + keySize + sigAlgo + san + "\n"
}