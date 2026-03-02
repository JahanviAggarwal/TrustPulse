package policy

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// evPolicyOID is the CA/B Forum EV TLS policy OID: 2.23.140.1.1
var evPolicyOID = stdasn1.ObjectIdentifier{2, 23, 140, 1, 1}

func enabledEVPolicy() *EVPolicy {
	return &EVPolicy{
		Enabled: true,
		RequiredSubjectFields: struct {
			Organization     bool `yaml:"organization"`
			Country          bool `yaml:"country"`
			BusinessCategory bool `yaml:"business_category"`
		}{
			Organization:     true,
			Country:          true,
			BusinessCategory: true,
		},
		RequiredEKUs: []zcrypto.ExtKeyUsage{zcrypto.ExtKeyUsageServerAuth},
	}
}

// evAwarePolicy returns DefaultPolicy with EV checking enabled.
// The EV rules check p.EV.Enabled from the *Policy argument, not r.Policy,
// so DefaultPolicy() (EV disabled) silently skips all EV checks.
func evAwarePolicy() *Policy {
	p := DefaultPolicy()
	p.EV = *enabledEVPolicy()
	return p
}

// ── IsEV helper ───────────────────────────────────────────────────────────────

func TestIsEV_True(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:    2048,
		dnsNames:   []string{"ev.example.com"},
		policyOIDs: []stdasn1.ObjectIdentifier{evPolicyOID},
	})
	require.True(t, IsEV(cert.ZCert),
		"expected IsEV=true for cert with OID 2.23.140.1.1; got PolicyIdentifiers=%v",
		cert.ZCert.PolicyIdentifiers)
}

func TestIsEV_False(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"tls.example.com"},
	})
	require.False(t, IsEV(cert.ZCert),
		"expected IsEV=false for cert without EV policy OID")
}

// ── RuleEV cert checks ────────────────────────────────────────────────────────

// TestRuleEV_Disabled_Skipped: DefaultPolicy has EV.Enabled=false, so the
// rule returns nil immediately.
func TestRuleEV_Disabled_Skipped(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:    2048,
		dnsNames:   []string{"ev.example.com"},
		policyOIDs: []stdasn1.ObjectIdentifier{evPolicyOID},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, DefaultPolicy()) // EV.Enabled=false in policy arg
	require.Empty(t, vs, "expected no violations when EV is disabled in the passed policy")
}

// TestRuleEV_NonEV_Skipped: cert without EV OID is skipped even when EV
// checking is active.
func TestRuleEV_NonEV_Skipped(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"tls.example.com"},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.Empty(t, vs, "expected no violations for non-EV cert (no EV policy OID)")
}

// buildCompliantEVCert satisfies all EV checks:
// Organization, Country, businessCategory (OID 2.5.4.15 — not OU),
// EV policy OID, and serverAuth EKU.
func buildCompliantEVCert(t *testing.T) *builtCert {
	t.Helper()
	return mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"ev.example.com"},
		subject: stdpkix.Name{
			Organization: []string{"ACME Corporation"},
			Country:      []string{"US"},
		},
		// businessCategory must be OID 2.5.4.15, not OrganizationalUnit (2.5.4.11)
		extraSubjectAttrs: []stdpkix.AttributeTypeAndValue{
			{Type: stdasn1.ObjectIdentifier{2, 5, 4, 15}, Value: "Private Organization"},
		},
		policyOIDs:   []stdasn1.ObjectIdentifier{evPolicyOID},
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	})
}

func TestRuleEV_AllPass(t *testing.T) {
	cert := buildCompliantEVCert(t)
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.Empty(t, vs, "expected no violations for fully compliant EV cert")
}

func TestRuleEV_OrgMissing_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"ev.example.com"},
		subject: stdpkix.Name{
			Country:            []string{"US"},
			OrganizationalUnit: []string{"Private Organization"},
			// Organization intentionally omitted
		},
		policyOIDs:   []stdasn1.ObjectIdentifier{evPolicyOID},
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-ORG-MISSING"),
		"expected EV-ORG-MISSING for EV cert without Organization")
}

func TestRuleEV_CountryMissing_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"ev.example.com"},
		subject: stdpkix.Name{
			Organization:       []string{"ACME Corporation"},
			OrganizationalUnit: []string{"Private Organization"},
			// Country intentionally omitted
		},
		policyOIDs:   []stdasn1.ObjectIdentifier{evPolicyOID},
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-COUNTRY-MISSING"),
		"expected EV-COUNTRY-MISSING for EV cert without Country")
}

// TestRuleEV_BusinessCategoryMissing_Fail: cert must have OID 2.5.4.15
// (businessCategory) in its Subject — having an OrganizationalUnit field
// is not sufficient and must not suppress the violation.
func TestRuleEV_BusinessCategoryMissing_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"ev.example.com"},
		subject: stdpkix.Name{
			Organization: []string{"ACME Corporation"},
			Country:      []string{"US"},
			// No businessCategory OID 2.5.4.15 → violation expected
		},
		policyOIDs:   []stdasn1.ObjectIdentifier{evPolicyOID},
		extKeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-BUSINESS-CATEGORY-MISSING"),
		"expected EV-BUSINESS-CATEGORY-MISSING for EV cert without businessCategory OID 2.5.4.15")
}

func TestRuleEV_EKUMissing_Fail(t *testing.T) {
	cert := mustBuildCert(t, &certOpts{
		keyBits:  2048,
		dnsNames: []string{"ev.example.com"},
		subject: stdpkix.Name{
			Organization:       []string{"ACME Corporation"},
			Country:            []string{"US"},
			OrganizationalUnit: []string{"Private Organization"},
		},
		policyOIDs: []stdasn1.ObjectIdentifier{evPolicyOID},
		// No extKeyUsages → serverAuth EKU is absent
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCert(cert.ZCert, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-EKU-MISSING"),
		"expected EV-EKU-MISSING for EV cert without serverAuth EKU")
}

// ── RuleEV CSR checks ─────────────────────────────────────────────────────────

func TestRuleEV_CSR_OrgMissing_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 2048,
		subject: stdpkix.Name{Country: []string{"US"}},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCSR(csr, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-ORG-MISSING"),
		"expected EV-ORG-MISSING for EV CSR without Organization")
}

func TestRuleEV_CSR_BusinessCategoryMissing_Fail(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 2048,
		subject: stdpkix.Name{
			Organization: []string{"ACME Corporation"},
			Country:      []string{"US"},
			// No OrganizationalUnit → businessCategory check fails
		},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCSR(csr, evAwarePolicy())
	require.True(t, ptrViolationsHaveID(vs, "EV-BUSINESS-CATEGORY-MISSING"),
		"expected EV-BUSINESS-CATEGORY-MISSING for EV CSR without OU")
}

func TestRuleEV_CSR_AllPass(t *testing.T) {
	csr := mustBuildCSR(t, &csrOpts{
		keyBits: 2048,
		// businessCategory (OID 2.5.4.15) via ExtraNames — not OrganizationalUnit
		subject: stdpkix.Name{
			Organization: []string{"ACME Corporation"},
			Country:      []string{"US"},
			ExtraNames: []stdpkix.AttributeTypeAndValue{
				{Type: stdasn1.ObjectIdentifier{2, 5, 4, 15}, Value: "Private Organization"},
			},
		},
	})
	rule := &RuleEV{Policy: enabledEVPolicy()}
	vs := rule.ValidateCSR(csr, evAwarePolicy())
	require.Empty(t, vs, "expected no violations for fully compliant EV CSR")
}