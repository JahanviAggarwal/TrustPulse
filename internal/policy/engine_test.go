package policy

import (
	stdpkix "crypto/x509/pkix"
	"testing"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	require.NotNil(t, e)
	require.Empty(t, e.rules)
}

func TestEngineRegister(t *testing.T) {
	e := NewEngine()
	e.Register(&RuleUniversalCert{Policy: &models.CertificatePolicy{}})
	require.Len(t, e.rules, 1)
}

func TestEngineEvaluateCert(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits: 1024,
		subject: stdpkix.Name{CommonName: "test.example.com"},
	})
	e := NewEngine()
	e.Register(&RuleUniversalCert{Policy: &models.CertificatePolicy{MinRSAKeySize: 2048}})
	vs := e.EvaluateCert(cert.ZCert, DefaultPolicy())
	require.Contains(t, violationIDs(vs), "CERT-KEY-001")
}

func TestEngineEvaluateCert_noRules(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{keyBits: 1024})
	e := NewEngine()
	require.Empty(t, e.EvaluateCert(cert.ZCert, DefaultPolicy()))
}

func TestEngineEvaluateCSR(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 1024,
		subject: stdpkix.Name{CommonName: "csr.example.com"},
	})
	e := NewEngine()
	e.Register(&RuleUniversalCSR{Policy: &models.CSRPolicy{MinRSAKeySize: 2048}})
	vs := e.EvaluateCSR(csr, DefaultPolicy())
	require.Contains(t, violationIDs(vs), "CSR-KEY-001")
}

func TestEngineEvaluateCSR_noRules(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{keyBits: 1024})
	e := NewEngine()
	require.Empty(t, e.EvaluateCSR(csr, DefaultPolicy()))
}

func TestBuildEngine(t *testing.T) {
	e := BuildEngine(DefaultPolicy())
	// universal cert, universal CSR, TLS, SMIME, EV, Root
	require.Len(t, e.rules, 6)
}

func TestBuildEngine_compliantCert(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"secure.example.com"},
	})
	p := DefaultPolicy()
	e := BuildEngine(p)
	for _, v := range e.EvaluateCert(cert.ZCert, p) {
		require.NotEqual(t, "CERT-KEY-001", v.RuleID)
	}
}

func TestClassicalAlgoOIDs(t *testing.T) {
	classical := []string{
		"1.2.840.113549.1.1.1",  // rsaEncryption
		"1.2.840.10045.2.1",     // id-ecPublicKey
		"1.3.101.112",           // id-Ed25519
		"1.3.101.113",           // id-Ed448
		"1.2.840.113549.1.1.11", // sha256WithRSAEncryption
	}
	for _, oid := range classical {
		require.True(t, isClassicalAlgoOID(oid), "expected classical: %s", oid)
	}
	require.False(t, isClassicalAlgoOID("9.9.9.9.9.9"))
	require.False(t, isClassicalAlgoOID("2.16.840.1.101.3.4.1.56"))
}

func violationIDs(vs []models.Violation) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.RuleID
	}
	return out
}