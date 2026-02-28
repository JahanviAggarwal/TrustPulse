package checks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/url"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
)

type CSRDetails struct {
	CommonName         string
	Organization       []string
	OrganizationalUnit []string
	Country            []string

	DNSNames    []string
	IPAddresses []string
	Emails      []string
	URIs        []string

	PublicKeyAlgorithm string
	SignatureAlgorithm string
	KeySize            int
}

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

func GetCSRDetails(csr *x509.CertificateRequest) (*CSRDetails, error) {
	if csr == nil {
		return nil, fmt.Errorf("csr is nil")
	}

	uris, err := GetCSRURIs(csr)
	if err != nil {
		fmt.Println("Error extracting URI SANs:", err)
		uris = []*url.URL{} // fallback to empty slice
	}

	// Convert []*url.URL to []string
	uriStrings := make([]string, len(uris))
	for i, u := range uris {
		uriStrings[i] = u.String()
	}

	details := &CSRDetails{
		CommonName:         csr.Subject.CommonName,
		Organization:       csr.Subject.Organization,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Country:            csr.Subject.Country,

		DNSNames: csr.DNSNames,
		Emails:   csr.EmailAddresses,
		URIs:     uriStrings,
	}

	// IP Addresses conversion
	for _, ip := range csr.IPAddresses {
		details.IPAddresses = append(details.IPAddresses, ip.String())
	}

	// Algorithms
	details.PublicKeyAlgorithm = csr.PublicKeyAlgorithm.String()
	details.SignatureAlgorithm = csr.SignatureAlgorithm.String()

	// Key size detection
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		details.KeySize = pub.Size() * 8 // RSA key size in bits
	default:
		details.KeySize = 0
	}

	return details, nil
}

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17} // SubjectAltName OID
// GetCSRURIs extracts URI SANs from a x509 CSR
func GetCSRURIs(csr *x509.CertificateRequest) ([]*url.URL, error) {
	var uris []*url.URL
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSAN) {
			// Parse the extension as a sequence of GeneralName
			var raw asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &raw)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal SAN extension: %v", err)
			}

			rest := raw.Bytes
			for len(rest) > 0 {
				var gn asn1.RawValue
				rest, err = asn1.Unmarshal(rest, &gn)
				if err != nil {
					return nil, fmt.Errorf("failed to parse GeneralName: %v", err)
				}

				// Tag 6 = URI
				if gn.Tag == 6 {
					u, err := url.Parse(string(gn.Bytes))
					if err != nil {
						continue
					}
					uris = append(uris, u)
				}
			}
		}
	}

	return uris, nil
}

// Helper to print URI SANs in CSR
func PrintCSRURIs(csr *x509.CertificateRequest) {
	uris, err := GetCSRURIs(csr)
	if err != nil {
		fmt.Println("Error extracting URI SANs:", err)
		return
	}
	if len(uris) == 0 {
		fmt.Println("No URI SANs in CSR")
	} else {
		fmt.Println("URI SANs in CSR:")
		for _, u := range uris {
			fmt.Println("-", u.String())
		}
	}
}

func (c *CSRDetails) String() string {
	return fmt.Sprintf(
		"CN: %s\nOrganization: %v\nOU: %v\nCountry: %v\nDNS: %v\nEmails: %v\nURIs: %v\n",
		c.CommonName,
		c.Organization,
		c.OrganizationalUnit,
		c.Country,
		c.DNSNames,
		c.Emails,
		c.URIs,
	)
}
