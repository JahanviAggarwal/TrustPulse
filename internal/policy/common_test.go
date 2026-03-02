package policy

import (
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zcrypto "github.com/zmap/zcrypto/x509"
)

// policyInfo is the ASN.1 shape of a single PolicyInformation (RFC 5280 §4.2.1.4).
type policyInfo struct {
	Policy stdasn1.ObjectIdentifier
}

// builtCert holds the zcrypto-parsed certificate alongside the stdlib-parsed
// form (with RawSubject populated) so it can be used as a signing parent.
type builtCert struct {
	ZCert   *zcrypto.Certificate
	StdCert *stdx509.Certificate
	Key     *rsa.PrivateKey
	DER     []byte
}

// certOpts drives mustBuildCert.
type certOpts struct {
	keyBits           int
	isCA              bool
	subject           stdpkix.Name
	extraSubjectAttrs []stdpkix.AttributeTypeAndValue // appended to Subject.ExtraNames
	dnsNames          []string
	ipAddresses       []net.IP
	emailAddresses    []string
	validDays         int
	keyUsage          stdx509.KeyUsage
	extKeyUsages      []stdx509.ExtKeyUsage
	policyOIDs        []stdasn1.ObjectIdentifier
	ocspServers       []string
	crlDPs            []string
	parent            *builtCert // nil → self-signed
}

// csrOpts drives mustBuildCSR.
type csrOpts struct {
	keyBits        int
	subject        stdpkix.Name
	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
}

// mustBuildCert constructs a synthetic certificate, signs it (self or by
// parent), and returns it parsed by both stdlib and zcrypto.
func mustBuildCert(t *testing.T, opts *certOpts) *builtCert {
	t.Helper()
	bits := opts.keyBits
	if bits == 0 {
		bits = 2048
	}
	days := opts.validDays
	if days == 0 {
		days = 365
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err, "mustBuildCert: rsa.GenerateKey")

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subj := opts.subject
	subj.ExtraNames = append(subj.ExtraNames, opts.extraSubjectAttrs...)

	tmpl := &stdx509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  opts.isCA,
		BasicConstraintsValid: true,
		KeyUsage:              opts.keyUsage,
		ExtKeyUsage:           opts.extKeyUsages,
		DNSNames:              opts.dnsNames,
		IPAddresses:           opts.ipAddresses,
		EmailAddresses:        opts.emailAddresses,
		OCSPServer:            opts.ocspServers,
		CRLDistributionPoints: opts.crlDPs,
	}

	// Encode Certificate Policies (2.5.29.32) via ExtraExtensions so the
	// extension is reliably included regardless of Go version behaviour
	// around PolicyIdentifiers vs Policies.
	if len(opts.policyOIDs) > 0 {
		infos := make([]policyInfo, len(opts.policyOIDs))
		for i, oid := range opts.policyOIDs {
			infos[i] = policyInfo{Policy: oid}
		}
		extVal, encErr := stdasn1.Marshal(infos)
		require.NoError(t, encErr, "mustBuildCert: marshal policyOIDs")
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, stdpkix.Extension{
			Id:    stdasn1.ObjectIdentifier{2, 5, 29, 32},
			Value: extVal,
		})
	}

	signerTmpl := tmpl
	signerKey := key
	if opts.parent != nil {
		signerTmpl = opts.parent.StdCert
		signerKey = opts.parent.Key
	}

	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, signerTmpl, &key.PublicKey, signerKey)
	require.NoError(t, err, "mustBuildCert: CreateCertificate")

	stdParsed, err := stdx509.ParseCertificate(der)
	require.NoError(t, err, "mustBuildCert: stdx509.ParseCertificate")

	zCert, err := zcrypto.ParseCertificate(der)
	require.NoError(t, err, "mustBuildCert: zcrypto.ParseCertificate")

	return &builtCert{ZCert: zCert, StdCert: stdParsed, Key: key, DER: der}
}

// mustBuildCSR constructs a synthetic CSR and returns it parsed by zcrypto.
func mustBuildCSR(t *testing.T, opts *csrOpts) *zcrypto.CertificateRequest {
	t.Helper()
	bits := opts.keyBits
	if bits == 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err, "mustBuildCSR: rsa.GenerateKey")

	tmpl := &stdx509.CertificateRequest{
		Subject:        opts.subject,
		DNSNames:       opts.dnsNames,
		EmailAddresses: opts.emailAddresses,
		IPAddresses:    opts.ipAddresses,
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err, "mustBuildCSR: CreateCertificateRequest")

	zCSR, err := zcrypto.ParseCertificateRequest(der)
	require.NoError(t, err, "mustBuildCSR: zcrypto.ParseCertificateRequest")

	return zCSR
}

// hasViolationID reports whether the flat Violation slice contains ruleID.
func hasViolationID(vs []Violation, ruleID string) bool {
	for _, v := range vs {
		if v.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ptrViolationsHaveID reports whether a []*Violation slice contains ruleID.
func ptrViolationsHaveID(vs []*Violation, ruleID string) bool {
	for _, v := range vs {
		if v != nil && v.RuleID == ruleID {
			return true
		}
	}
	return false
}