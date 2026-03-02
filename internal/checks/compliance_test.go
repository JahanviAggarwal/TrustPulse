package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

func buildRSACert(t *testing.T, dnsNames []string, emails []string, ips []net.IP) *zcrypto.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &stdx509.Certificate{
		SerialNumber:   serial,
		Subject:        stdpkix.Name{CommonName: "test.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		IPAddresses:    ips,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := zcrypto.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func buildRSACSR(t *testing.T, subject stdpkix.Name, dnsNames []string, emails []string, ips []net.IP, bits int) *zcrypto.CertificateRequest {
	t.Helper()
	if bits == 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	tmpl := &stdx509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		IPAddresses:    ips,
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csr, err := zcrypto.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// GetCertificateDetails tests

func TestCertDetails_RSA(t *testing.T) {
	cert := buildRSACert(t, []string{"example.com"}, nil, nil)
	details := GetCertificateDetails(cert)
	require.Contains(t, details, "RSA")
	require.Contains(t, details, "2048")
}

func TestCertDetails_dnsSAN(t *testing.T) {
	cert := buildRSACert(t, []string{"example.com", "www.example.com"}, nil, nil)
	details := GetCertificateDetails(cert)
	require.Contains(t, details, "DNS:example.com")
	require.Contains(t, details, "DNS:www.example.com")
}

func TestCertDetails_ipSAN(t *testing.T) {
	cert := buildRSACert(t, nil, nil, []net.IP{net.ParseIP("10.0.0.1")})
	require.Contains(t, GetCertificateDetails(cert), "IP:10.0.0.1")
}

func TestCertDetails_emailSAN(t *testing.T) {
	cert := buildRSACert(t, nil, []string{"user@example.com"}, nil)
	require.Contains(t, GetCertificateDetails(cert), "email:user@example.com")
}

func TestCertDetails_noSAN(t *testing.T) {
	cert := buildRSACert(t, nil, nil, nil)
	require.Contains(t, GetCertificateDetails(cert), "SANs: None")
}

func TestCertDetails_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &stdx509.Certificate{
		SerialNumber: serial,
		Subject:      stdpkix.Name{CommonName: "ecdsa.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"ecdsa.example.com"},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := zcrypto.ParseCertificate(der)
	require.NoError(t, err)

	details := GetCertificateDetails(cert)
	require.Contains(t, details, "ECDSA")
	require.Contains(t, details, "256")
}

func TestCertDetails_validity(t *testing.T) {
	cert := buildRSACert(t, []string{"example.com"}, nil, nil)
	require.Contains(t, GetCertificateDetails(cert), "Validity:")
}

// GetCSRDetails tests

func TestCSRDetails_nil(t *testing.T) {
	_, err := GetCSRDetails(nil)
	require.Error(t, err)
}

func TestCSRDetails_RSA2048(t *testing.T) {
	csr := buildRSACSR(t,
		stdpkix.Name{CommonName: "csr.example.com", Organization: []string{"ACME"}},
		[]string{"csr.example.com"}, nil, nil, 2048)
	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Equal(t, 2048, d.KeySize)
	require.Equal(t, "csr.example.com", d.CommonName)
	require.Equal(t, []string{"ACME"}, d.Organization)
	require.Contains(t, d.DNSNames, "csr.example.com")
}

func TestCSRDetails_RSA1024(t *testing.T) {
	csr := buildRSACSR(t, stdpkix.Name{CommonName: "small.example.com"},
		[]string{"small.example.com"}, nil, nil, 1024)
	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Equal(t, 1024, d.KeySize)
}

func TestCSRDetails_ECDSAP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &stdx509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: "ecdsa-csr.example.com"},
		DNSNames: []string{"ecdsa-csr.example.com"},
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csr, err := zcrypto.ParseCertificateRequest(der)
	require.NoError(t, err)

	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Equal(t, 256, d.KeySize)
}

func TestCSRDetails_ipAddresses(t *testing.T) {
	csr := buildRSACSR(t, stdpkix.Name{CommonName: "ip.example.com"},
		nil, nil, []net.IP{net.ParseIP("192.168.1.1")}, 2048)
	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Contains(t, d.IPAddresses, "192.168.1.1")
}

func TestCSRDetails_emailAddresses(t *testing.T) {
	csr := buildRSACSR(t, stdpkix.Name{CommonName: "email.example.com"},
		nil, []string{"user@example.com"}, nil, 2048)
	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Contains(t, d.Emails, "user@example.com")
}

func TestCSRDetails_subjectFields(t *testing.T) {
	csr := buildRSACSR(t,
		stdpkix.Name{
			CommonName:         "full.example.com",
			Organization:       []string{"ACME Corp"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
		},
		[]string{"full.example.com"}, nil, nil, 2048)
	d, err := GetCSRDetails(csr)
	require.NoError(t, err)
	require.Equal(t, "full.example.com", d.CommonName)
	require.Equal(t, []string{"ACME Corp"}, d.Organization)
	require.Equal(t, []string{"Engineering"}, d.OrganizationalUnit)
	require.Equal(t, []string{"US"}, d.Country)
}

func TestCSRDetails_String(t *testing.T) {
	d := &CSRDetails{
		CommonName:   "test.example.com",
		Organization: []string{"ACME Corp"},
		DNSNames:     []string{"test.example.com"},
	}
	s := d.String()
	require.Contains(t, s, "test.example.com")
	require.Contains(t, s, "ACME Corp")
}

func TestCSRDetails_String_empty(t *testing.T) {
	require.NotEmpty(t, (&CSRDetails{}).String())
}

func TestGetCSRURIs_noURI(t *testing.T) {
	csr := buildRSACSR(t,
		stdpkix.Name{CommonName: "no-uri.example.com"},
		[]string{"no-uri.example.com"}, nil, nil, 2048)
	uris, err := GetCSRURIs(csr)
	require.NoError(t, err)
	require.Empty(t, uris)
}