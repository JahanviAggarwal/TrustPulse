package policy

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"testing"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

func enabledSMIMEPolicy() *models.SMIMEPolicy {
	return &models.SMIMEPolicy{
		Enabled:                 true,
		RequireEKU:              []zcrypto.ExtKeyUsage{zcrypto.ExtKeyUsageEmailProtection},
		RequireEmail:            true,
		RequireRevocation:       true,
		RequireDigitalSignature: true,
	}
}

func TestRuleSMIME_Disabled_Skipped(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits: 2048,
		subject: stdpkix.Name{CommonName: "no-smime.example.com"},
	})
	rule := &RuleSMIME{Policy: &models.SMIMEPolicy{Enabled: false}}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.Empty(t, vs, "expected no violations when S/MIME policy is disabled")
}

func TestRuleSMIME_NonSMIME_Skipped(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:      2048,
		dnsNames:     []string{"tls.example.com"},
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.Empty(t, vs, "expected no violations for non-S/MIME cert (no emailProtection EKU)")
}

func TestRuleSMIME_AllPass(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
		keyUsage:       stdx509.KeyUsageDigitalSignature,
		extKeyUsages:   []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		ocspServers:    []string{"http://ocsp.example.com"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.Empty(t, vs, "expected no violations for fully compliant S/MIME cert")
}

func TestRuleSMIME_EKU_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
		keyUsage:       stdx509.KeyUsageDigitalSignature,
		// emailProtection makes IsSMIME return true
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		ocspServers:  []string{"http://ocsp.example.com"},
	})
	// Policy requires clientAuth — cert only has emailProtection → missing
	p := enabledSMIMEPolicy()
	p.RequireEKU = []zcrypto.ExtKeyUsage{zcrypto.ExtKeyUsageClientAuth}
	rule := &RuleSMIME{Policy: p}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "SMIME-EKU-MISSING"),
		"expected SMIME-EKU-MISSING when required EKU (clientAuth) is absent")
}

func TestRuleSMIME_Email_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:      2048,
		dnsNames:     []string{"smime.example.com"}, // no email SAN
		keyUsage:     stdx509.KeyUsageDigitalSignature,
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		ocspServers:  []string{"http://ocsp.example.com"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "SMIME-SAN-MISSING"),
		"expected SMIME-SAN-MISSING for cert without email SAN")
}

func TestRuleSMIME_DigitalSignature_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
		keyUsage:       stdx509.KeyUsageKeyEncipherment, // no digitalSignature
		extKeyUsages:   []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		ocspServers:    []string{"http://ocsp.example.com"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "SMIME-KEYUSAGE-INVALID"),
		"expected SMIME-KEYUSAGE-INVALID for cert without digitalSignature")
}

func TestRuleSMIME_Revocation_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
		keyUsage:       stdx509.KeyUsageDigitalSignature,
		extKeyUsages:   []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		// no ocspServers, no crlDPs
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "SMIME-REVOCATION-MISSING"),
		"expected SMIME-REVOCATION-MISSING for cert without OCSP or CRL")
}

func TestRuleSMIME_CRL_Satisfies_Revocation(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
		keyUsage:       stdx509.KeyUsageDigitalSignature,
		extKeyUsages:   []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection},
		crlDPs:         []string{"http://crl.example.com/root.crl"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "SMIME-REVOCATION-MISSING"),
		"expected no SMIME-REVOCATION-MISSING when CRL DP is present")
}

func TestRuleSMIME_CSR_Pass(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:        2048,
		emailAddresses: []string{"user@example.com"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCSR(csr, DefaultPolicy())
	require.False(t, ptrViolationsHaveID(vs, "SMIME-SAN-MISSING"),
		"expected no SMIME-SAN-MISSING for CSR with email SAN")
}

func TestRuleSMIME_CSR_NoEmail_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits:  2048,
		dnsNames: []string{"smime.example.com"},
	})
	rule := &RuleSMIME{Policy: enabledSMIMEPolicy()}
	vs := rule.ValidateCSR(csr, DefaultPolicy())
	require.True(t, ptrViolationsHaveID(vs, "SMIME-SAN-MISSING"),
		"expected SMIME-SAN-MISSING for CSR without email SAN")
}