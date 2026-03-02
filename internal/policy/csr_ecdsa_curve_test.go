package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// mustBuildECDSACSR generates a self-signed CSR with the given ECDSA curve.
func mustBuildECDSACSR(t *testing.T, curve elliptic.Curve, dnsNames []string) *zcrypto.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	tmpl := &stdx509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: "ecdsa-csr.example.com"},
		DNSNames: dnsNames,
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)

	csr, err := zcrypto.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

func TestCSRECDSACurve_P256_pass(t *testing.T) {
	csr := mustBuildECDSACSR(t, elliptic.P256(), []string{"example.com"})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"P-256 CSR should pass a 256-bit minimum")
}

func TestCSRECDSACurve_P384_pass(t *testing.T) {
	csr := mustBuildECDSACSR(t, elliptic.P384(), []string{"example.com"})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"P-384 CSR should pass a 256-bit minimum")
}

func TestCSRECDSACurve_P224_fail(t *testing.T) {
	// P-224 is 224 bits; policy requires at least 256
	csr := mustBuildECDSACSR(t, elliptic.P224(), []string{"example.com"})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 256
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"P-224 CSR should be rejected when minimum is 256 bits")
}

func TestCSRECDSACurve_P256_highMin_fail(t *testing.T) {
	// P-256 is below a 384-bit minimum
	csr := mustBuildECDSACSR(t, elliptic.P256(), []string{"example.com"})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 384
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"P-256 CSR should be rejected when minimum is 384 bits")
}

func TestCSRECDSACurve_disabled(t *testing.T) {
	// MinECDSACurveBits=0 disables the check
	csr := mustBuildECDSACSR(t, elliptic.P224(), []string{"example.com"})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 0
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"ECDSA curve check should be skipped when MinECDSACurveBits=0")
}

func TestCSRECDSACurve_RSANotAffected(t *testing.T) {
	// The curve check must not fire for RSA CSRs regardless of MinECDSACurveBits
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:  2048,
		dnsNames: []string{"rsa.example.com"},
	})
	p := defaultCSRPolicy()
	p.MinECDSACurveBits = 521
	vs := (&RuleUniversalCSR{Policy: p}).ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-ECDSA-CURVE-001"),
		"RSA CSR should not trigger ECDSA curve check")
}