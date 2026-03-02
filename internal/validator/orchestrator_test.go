package validator

import (
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/stretchr/testify/require"
)

// writePEM encodes DER bytes as a PEM block in a temp file and returns the path.
func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "trustpulse-*.pem")
	require.NoError(t, err, "writePEM: CreateTemp")
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}), "writePEM: pem.Encode")
	f.Close()
	return f.Name()
}

// buildSelfSignedCACert returns DER-encoded self-signed CA cert bytes.
func buildSelfSignedCACert(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &stdx509.Certificate{
		SerialNumber:          serial,
		Subject:               stdpkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
		DNSNames:              []string{"ca.example.com"},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// buildCSRBytes returns DER-encoded CSR bytes.
func buildCSRBytes(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &stdx509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return der
}

func TestRunAudit_Certificate(t *testing.T) {
	path := writePEM(t, "CERTIFICATE", buildSelfSignedCACert(t))
	report, err := RunAudit(path, policy.DefaultPolicy())
	require.NoError(t, err, "RunAudit should not return an error for a valid certificate")
	require.NotNil(t, report, "RunAudit should return a non-nil report")
}

func TestRunAudit_CSR(t *testing.T) {
	path := writePEM(t, "CERTIFICATE REQUEST", buildCSRBytes(t))
	report, err := RunAudit(path, policy.DefaultPolicy())
	require.NoError(t, err, "RunAudit should not return an error for a valid CSR")
	require.NotNil(t, report, "RunAudit should return a non-nil report")
}

func TestRunAudit_FileNotFound(t *testing.T) {
	_, err := RunAudit(filepath.Join(t.TempDir(), "nonexistent.pem"), policy.DefaultPolicy())
	require.Error(t, err, "expected error for non-existent file")
}

func TestRunAudit_InvalidPEM(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.pem")
	require.NoError(t, err)
	_, _ = f.WriteString("this is not PEM content")
	f.Close()

	_, err = RunAudit(f.Name(), policy.DefaultPolicy())
	require.Error(t, err, "expected error for non-PEM file content")
}

func TestRunAudit_UnsupportedPEMType(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "unknown-*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("dummy")}))
	f.Close()

	_, err = RunAudit(f.Name(), policy.DefaultPolicy())
	require.Error(t, err, "expected error for unsupported PEM type")
}

func TestReport_ShouldFail_AuditMode(t *testing.T) {
	path := writePEM(t, "CERTIFICATE", buildSelfSignedCACert(t))
	p := policy.DefaultPolicy()
	report, err := RunAudit(path, p)
	require.NoError(t, err)
	require.False(t, report.ShouldFail(p, "audit"),
		"ShouldFail must return false in audit mode regardless of violations")
}

func TestReport_ShouldFail_PreissuanceMode(t *testing.T) {
	// CSR with no SAN → triggers CSR-SAN-001 (HIGH)
	p := policy.DefaultPolicy()
	p.Enforcement.Mode = "preissuance"
	p.Enforcement.FailOn = []models.Severity{models.SeverityHigh}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &stdx509.CertificateRequest{
		Subject: stdpkix.Name{CommonName: "no-san.example.com"},
	}
	der, err := stdx509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	path := writePEM(t, "CERTIFICATE REQUEST", der)

	report, err := RunAudit(path, p)
	require.NoError(t, err)
	require.True(t, report.ShouldFail(p, "preissuance"),
		"ShouldFail should return true in preissuance mode with HIGH violations")
}

func TestReport_JSON_ValidOutput(t *testing.T) {
	path := writePEM(t, "CERTIFICATE REQUEST", buildCSRBytes(t))
	p := policy.DefaultPolicy()
	report, err := RunAudit(path, p)
	require.NoError(t, err)

	jsonStr, err := report.JSON(p, "audit")
	require.NoError(t, err)
	require.NotEmpty(t, jsonStr, "Report.JSON should return non-empty JSON output")
}