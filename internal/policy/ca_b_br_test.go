package policy

import (
	stdpkix "crypto/x509/pkix"
	"net"
	"testing"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
)

func defaultCertPolicy() *models.CertificatePolicy {
	return &models.CertificatePolicy{
		MinRSAKeySize:              2048,
		MaxValidityDays:            398,
		RequireSAN:                 true,
		AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
	}
}

func defaultCSRPolicy() *models.CSRPolicy {
	return &models.CSRPolicy{
		MinRSAKeySize:              2048,
		RequireSAN:                 true,
		AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
	}
}

// ── RuleUniversalCert ────────────────────────────────────────────────────────

func TestRuleUniversalCert_RSAKeySize_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
		subject:  stdpkix.Name{CommonName: "example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-KEY-001"),
		"expected no CERT-KEY-001 for 2048-bit key")
}

func TestRuleUniversalCert_RSAKeySize_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  1024,
		dnsNames: []string{"example.com"},
		subject:  stdpkix.Name{CommonName: "example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-KEY-001"),
		"expected CERT-KEY-001 for 1024-bit key")
}

func TestRuleUniversalCert_Validity_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:   2048,
		validDays: 365,
		dnsNames:  []string{"example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-VAL-001"),
		"expected no CERT-VAL-001 for 365-day cert")
}

func TestRuleUniversalCert_Validity_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:   2048,
		validDays: 400,
		dnsNames:  []string{"example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-VAL-001"),
		"expected CERT-VAL-001 for 400-day cert")
}

func TestRuleUniversalCert_SAN_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-SAN-001"),
		"expected no CERT-SAN-001 when DNS SAN is present")
}

func TestRuleUniversalCert_SAN_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits: 2048,
		subject: stdpkix.Name{CommonName: "no-san.example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-SAN-001"),
		"expected CERT-SAN-001 for cert with no SAN")
}

func TestRuleUniversalCert_SigAlgo_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
	})
	rule := &RuleUniversalCert{Policy: defaultCertPolicy()}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CERT-SIG-001"),
		"expected no CERT-SIG-001 for SHA256-RSA cert (algo: %s)", cert.ZCert.SignatureAlgorithm.String())
}

func TestRuleUniversalCert_SigAlgo_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
	})
	p := defaultCertPolicy()
	p.AllowedSignatureAlgorithms = []string{"ECDSA-SHA256"}
	rule := &RuleUniversalCert{Policy: p}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CERT-SIG-001"),
		"expected CERT-SIG-001 for RSA cert with ECDSA-only policy")
}

func TestRuleUniversalCert_NilPolicy_Safe(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{keyBits: 2048})
	rule := &RuleUniversalCert{Policy: nil}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.Empty(t, vs, "expected no violations for nil policy")
}

// ── RuleTLSServerCert ────────────────────────────────────────────────────────

func TestRuleTLSServerCert_DNSAN_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"secure.example.com"},
	})
	rule := &RuleTLSServerCert{Policy: &models.TLSServerPolicy{RequireSAN: true}}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "TLS-SAN-001"),
		"expected no TLS-SAN-001 when DNS SAN is present")
}

func TestRuleTLSServerCert_IPSAN_Pass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:     2048,
		ipAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	})
	rule := &RuleTLSServerCert{Policy: &models.TLSServerPolicy{RequireSAN: true}}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "TLS-SAN-001"),
		"expected no TLS-SAN-001 when IP SAN is present")
}

func TestRuleTLSServerCert_NoSAN_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits: 2048,
		subject: stdpkix.Name{CommonName: "tls.example.com"},
	})
	rule := &RuleTLSServerCert{Policy: &models.TLSServerPolicy{RequireSAN: true}}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "TLS-SAN-001"),
		"expected TLS-SAN-001 for TLS cert with no DNS/IP SAN")
}

func TestRuleTLSServerCert_EmailOnlySAN_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
	})
	rule := &RuleTLSServerCert{Policy: &models.TLSServerPolicy{RequireSAN: true}}
	vs := rule.ValidateCert(cert.ZCert, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "TLS-SAN-001"),
		"expected TLS-SAN-001 for cert with email-only SAN (not DNS/IP)")
}

func TestRuleTLSServerCert_CSR_NoSAN_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		subject: stdpkix.Name{CommonName: "tls.example.com"},
	})
	rule := &RuleTLSServerCert{Policy: &models.TLSServerPolicy{RequireSAN: true}}
	vs := rule.ValidateCSR(csr, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "TLS-CSR-SAN-001"),
		"expected TLS-CSR-SAN-001 for TLS CSR with no DNS/IP SAN")
}

// ── RuleUniversalCSR ─────────────────────────────────────────────────────────

func TestRuleUniversalCSR_KeySize_Pass(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
	})
	rule := &RuleUniversalCSR{Policy: defaultCSRPolicy()}
	vs := rule.ValidateCSR(csr, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-KEY-001"),
		"expected no CSR-KEY-001 for 2048-bit CSR")
}

func TestRuleUniversalCSR_KeySize_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:  1024,
		dnsNames: []string{"example.com"},
	})
	rule := &RuleUniversalCSR{Policy: defaultCSRPolicy()}
	vs := rule.ValidateCSR(csr, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CSR-KEY-001"),
		"expected CSR-KEY-001 for 1024-bit CSR")
}

func TestRuleUniversalCSR_SAN_Pass(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:  2048,
		dnsNames: []string{"example.com"},
	})
	rule := &RuleUniversalCSR{Policy: defaultCSRPolicy()}
	vs := rule.ValidateCSR(csr, testPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-SAN-001"),
		"expected no CSR-SAN-001 when DNS SAN is present")
}

func TestRuleUniversalCSR_SAN_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 2048,
		subject: stdpkix.Name{CommonName: "no-san.example.com"},
	})
	rule := &RuleUniversalCSR{Policy: defaultCSRPolicy()}
	vs := rule.ValidateCSR(csr, testPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CSR-SAN-001"),
		"expected CSR-SAN-001 for CSR with no SAN")
}