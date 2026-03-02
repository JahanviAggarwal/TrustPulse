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

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// mustBuildECDSACA creates a self-signed ECDSA CA certificate for testing.
func mustBuildECDSACA(t *testing.T, curve elliptic.Curve) *zcrypto.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &stdx509.Certificate{
		SerialNumber:          serial,
		Subject:               stdpkix.Name{CommonName: "ECDSA Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := zcrypto.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func rootPolicyWithECDSA(minRSA, minECDSA int) *models.RootPolicy {
	return &models.RootPolicy{
		Enabled:                 true,
		MinRSAKeySize:           minRSA,
		MinECDSACurveBits:       minECDSA,
		RequireSelfSigned:       true,
		RequireKeyUsageCertSign: true,
	}
}

func TestRuleRoot_ECDSACurve_P384_pass(t *testing.T) {
	ca := mustBuildECDSACA(t, elliptic.P384())
	rule := &RuleRoot{Policy: rootPolicyWithECDSA(4096, 384)}
	vs := rule.ValidateCert(ca, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "ROOT-ECDSA-CURVE"),
		"P-384 root CA should pass a 384-bit minimum")
}

func TestRuleRoot_ECDSACurve_P521_pass(t *testing.T) {
	ca := mustBuildECDSACA(t, elliptic.P521())
	rule := &RuleRoot{Policy: rootPolicyWithECDSA(4096, 384)}
	vs := rule.ValidateCert(ca, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "ROOT-ECDSA-CURVE"),
		"P-521 root CA should pass a 384-bit minimum")
}

func TestRuleRoot_ECDSACurve_P256_fail(t *testing.T) {
	// P-256 (256 bits) is below the 384-bit minimum for root CAs
	ca := mustBuildECDSACA(t, elliptic.P256())
	rule := &RuleRoot{Policy: rootPolicyWithECDSA(4096, 384)}
	vs := rule.ValidateCert(ca, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "ROOT-ECDSA-CURVE"),
		"P-256 root CA should be rejected when minimum is 384 bits")
}

func TestRuleRoot_ECDSACurve_P224_fail(t *testing.T) {
	ca := mustBuildECDSACA(t, elliptic.P224())
	rule := &RuleRoot{Policy: rootPolicyWithECDSA(4096, 256)}
	vs := rule.ValidateCert(ca, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "ROOT-ECDSA-CURVE"),
		"P-224 root CA should be rejected when minimum is 256 bits")
}

func TestRuleRoot_ECDSACurve_disabled(t *testing.T) {
	// MinECDSACurveBits=0 disables the check — even P-224 should pass
	ca := mustBuildECDSACA(t, elliptic.P224())
	rule := &RuleRoot{Policy: rootPolicyWithECDSA(4096, 0)}
	vs := rule.ValidateCert(ca, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "ROOT-ECDSA-CURVE"),
		"ECDSA curve check should be skipped when MinECDSACurveBits=0")
}