package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// mustBuildECDSACert creates a self-signed ECDSA certificate for testing.
func mustBuildECDSACert(t *testing.T, curve elliptic.Curve, dnsNames []string) *zcrypto.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &stdx509.Certificate{
		SerialNumber:          serial,
		Subject:               stdpkix.Name{CommonName: "ecdsa.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := zcrypto.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestECDSACurve_P256_pass(t *testing.T) {
	cert := mustBuildECDSACert(t, elliptic.P256(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"))
}

func TestECDSACurve_P384_pass(t *testing.T) {
	cert := mustBuildECDSACert(t, elliptic.P384(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"))
}

func TestECDSACurve_P224_fail(t *testing.T) {
	// P-224 is 224 bits; policy requires at least 256
	cert := mustBuildECDSACert(t, elliptic.P224(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"),
		"P-224 should be rejected when minimum is 256 bits")
}

func TestECDSACurve_disabled(t *testing.T) {
	// MinECDSACurveBits=0 means the check is off
	cert := mustBuildECDSACert(t, elliptic.P224(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 0
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"))
}

func TestECDSACurve_P521_highMin_pass(t *testing.T) {
	cert := mustBuildECDSACert(t, elliptic.P521(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 384
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"))
}

func TestECDSACurve_P256_highMin_fail(t *testing.T) {
	cert := mustBuildECDSACert(t, elliptic.P256(), []string{"ecdsa.example.com"})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 384
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"),
		"P-256 should be rejected when minimum is 384 bits")
}

func TestECDSACurve_RSANotAffected(t *testing.T) {
	// The curve check must not fire for RSA certs regardless of MinECDSACurveBits
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"rsa.example.com"},
	})
	p := defaultCertPolicy()
	p.MinECDSACurveBits = 521
	vs := (&RuleUniversalCert{Policy: p}).ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-ECDSA-CURVE-001"))
}