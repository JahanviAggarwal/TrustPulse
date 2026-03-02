package policy

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"testing"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
)

func rootPolicy(minKeyBits int) *models.RootPolicy {
	return &models.RootPolicy{
		Enabled:                 true,
		MinRSAKeySize:           minKeyBits,
		RequireSelfSigned:       true,
		RequireKeyUsageCertSign: true,
	}
}

func TestRuleRoot_LeafCert_Skipped(t *testing.T) {
	leaf := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     false,
		dnsNames: []string{"leaf.example.com"},
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(leaf.ZCert, DefaultPolicy())
	require.Empty(t, vs, "expected no violations for a non-CA leaf cert")
}

func TestRuleRoot_Disabled(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  1024,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign,
	})
	p := rootPolicy(2048)
	p.Enabled = false
	rule := &RuleRoot{Policy: p}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.Empty(t, vs, "expected no violations when root policy is disabled")
}

func TestRuleRoot_SelfSigned_Pass(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "ROOT-NOT-SELF-SIGNED"),
		"expected no ROOT-NOT-SELF-SIGNED for a self-signed CA")
}

func TestRuleRoot_NotSelfSigned_Fail(t *testing.T) {
	root := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	})
	intermediate := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Intermediate CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
		parent:   root,
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(intermediate.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "ROOT-NOT-SELF-SIGNED"),
		"expected ROOT-NOT-SELF-SIGNED for intermediate CA signed by a different key")
}

func TestRuleRoot_KeySize_Pass(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "ROOT-KEY-SIZE"),
		"expected no ROOT-KEY-SIZE for 2048-bit root with 2048-bit minimum")
}

func TestRuleRoot_KeySize_Fail(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  1024,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "ROOT-KEY-SIZE"),
		"expected ROOT-KEY-SIZE for 1024-bit root with 2048-bit minimum")
}

func TestRuleRoot_KeyUsageCertSign_Pass(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "RFC5280-CA-KEYUSAGE"),
		"expected no RFC5280-CA-KEYUSAGE when keyCertSign is set")
}

func TestRuleRoot_KeyUsageCertSign_Fail(t *testing.T) {
	ca := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		isCA:     true,
		subject:  stdpkix.Name{CommonName: "Root CA"},
		keyUsage: stdx509.KeyUsageCRLSign, // no CertSign
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCert(ca.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "RFC5280-CA-KEYUSAGE"),
		"expected RFC5280-CA-KEYUSAGE for CA without keyCertSign")
}

func TestRuleRoot_CSR_KeySize_Pass(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 2048,
		subject: stdpkix.Name{CommonName: "Root CA"},
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "CSR-ROOT-KEY-001"),
		"expected no CSR-ROOT-KEY-001 for 2048-bit CSR")
}

func TestRuleRoot_CSR_KeySize_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 1024,
		subject: stdpkix.Name{CommonName: "Root CA"},
	})
	rule := &RuleRoot{Policy: rootPolicy(2048)}
	vs := rule.ValidateCSR(csr, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "CSR-ROOT-KEY-001"),
		"expected CSR-ROOT-KEY-001 for 1024-bit CSR")
}