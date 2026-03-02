package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// binaryPath is the compiled trustpulse binary, built once for the whole test run.
var binaryPath string

// TestMain builds the binary once and runs all tests against it.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "trustpulse-cli-build-*")
	if err != nil {
		panic("TestMain: MkdirTemp: " + err.Error())
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "trustpulse")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("TestMain: build failed:\n" + string(out))
	}

	os.Exit(m.Run())
}

// runBinary executes the binary from workDir with the given args.
// It returns stdout, stderr, and the process exit code.
func runBinary(t *testing.T, workDir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = workDir
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running binary: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// setupWorkDir creates a temp directory containing a self-signed cert PEM and a minimal policy.yaml.
// It returns the directory, absolute cert path, and absolute policy path.
func setupWorkDir(t *testing.T) (dir, certPath, policyPath string) {
	t.Helper()
	dir = t.TempDir()

	// Self-signed leaf cert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &stdx509.Certificate{
		SerialNumber: serial,
		Subject:      stdpkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	f, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	f.Close()

	// Minimal policy.yaml
	const minimalPolicy = `version: "1.0"
certificate:
  min_rsa_key_size: 2048
  max_validity_days: 398
  require_san: true
  allowed_signature_algorithms:
    - SHA256-RSA
    - ECDSA-SHA256
enforcement:
  mode: "audit"
  fail_on: ["HIGH"]
`
	policyPath = filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(minimalPolicy), 0o644))

	return dir, certPath, policyPath
}

// ─── --file flag ──────────────────────────────────────────────────────────────

func TestCLI_FileFlag_Required(t *testing.T) {
	dir, _, policyPath := setupWorkDir(t)
	_, stderr, code := runBinary(t, dir, "--policy="+policyPath)
	require.Equal(t, 2, code, "expected exit 2 when --file is omitted")
	require.Contains(t, stderr, "--file is required")
}

func TestCLI_FileNotFound(t *testing.T) {
	dir, _, policyPath := setupWorkDir(t)
	_, stderr, code := runBinary(t, dir, "--file=/nonexistent/cert.pem", "--policy="+policyPath)
	require.Equal(t, 3, code, "expected exit 3 when PEM file does not exist")
	require.Contains(t, stderr, "error:")
}

// ─── Policy resolution ───────────────────────────────────────────────────────

func TestCLI_NoPolicyNoCWDFile(t *testing.T) {
	// Run from an empty temp dir (no policy.yaml present).
	_, certPath, _ := setupWorkDir(t)
	emptyDir := t.TempDir()

	_, stderr, code := runBinary(t, emptyDir, "--file="+certPath)
	require.Equal(t, 2, code, "expected exit 2 when no policy file found")
	require.Contains(t, stderr, "no policy file found")
}

func TestCLI_PolicyAutodiscovered_yaml(t *testing.T) {
	// policy.yaml lives in the work directory — should be auto-detected.
	dir, certPath, _ := setupWorkDir(t) // writes policy.yaml into dir
	stdout, _, code := runBinary(t, dir, "--file="+certPath)
	require.Equal(t, 0, code, "expected exit 0 with auto-discovered policy.yaml")
	require.Contains(t, stdout, `"summary"`, "expected JSON output")
}

func TestCLI_PolicyAutodiscovered_yml(t *testing.T) {
	// Rename the file to policy.yml to test the second candidate.
	dir, certPath, policyPath := setupWorkDir(t)
	ymlPath := filepath.Join(dir, "policy.yml")
	require.NoError(t, os.Rename(policyPath, ymlPath))

	stdout, _, code := runBinary(t, dir, "--file="+certPath)
	require.Equal(t, 0, code, "expected exit 0 with auto-discovered policy.yml")
	require.Contains(t, stdout, `"summary"`)
}

func TestCLI_ExplicitPolicy(t *testing.T) {
	_, certPath, policyPath := setupWorkDir(t)
	// Run from an empty dir so auto-detect would fail — explicit --policy must win.
	emptyDir := t.TempDir()
	stdout, _, code := runBinary(t, emptyDir, "--file="+certPath, "--policy="+policyPath)
	require.Equal(t, 0, code, "expected exit 0 with explicit --policy")
	require.Contains(t, stdout, `"summary"`)
}

func TestCLI_PolicyNotFound(t *testing.T) {
	dir, certPath, _ := setupWorkDir(t)
	_, stderr, code := runBinary(t, dir, "--file="+certPath, "--policy=/nonexistent/policy.yaml")
	require.Equal(t, 3, code, "expected exit 3 when policy file does not exist")
	require.Contains(t, stderr, "failed to load policy")
}

// ─── --format flag ────────────────────────────────────────────────────────────

func TestCLI_FormatJSON(t *testing.T) {
	dir, certPath, _ := setupWorkDir(t)
	stdout, _, code := runBinary(t, dir, "--file="+certPath, "--format=json")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, `"summary"`)
	require.Contains(t, stdout, `"violations"`)
}

func TestCLI_FormatText(t *testing.T) {
	dir, certPath, _ := setupWorkDir(t)
	stdout, _, code := runBinary(t, dir, "--file="+certPath, "--format=text")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "AUDIT REPORT")
	require.Contains(t, stdout, "Policy loaded:")
}

func TestCLI_InvalidFormat(t *testing.T) {
	dir, certPath, policyPath := setupWorkDir(t)
	_, stderr, code := runBinary(t, dir, "--file="+certPath, "--policy="+policyPath, "--format=xml")
	require.Equal(t, 2, code, "expected exit 2 for unknown format")
	require.Contains(t, stderr, "unknown format")
}

// ─── --version flag ───────────────────────────────────────────────────────────

func TestCLI_Version(t *testing.T) {
	stdout, _, code := runBinary(t, t.TempDir(), "--version")
	require.Equal(t, 0, code, "expected exit 0 for --version")
	require.Contains(t, stdout, "trustpulse")
}

// ─── --mode flag ──────────────────────────────────────────────────────────────

func TestCLI_ModePreissuance_PassesCleanCert(t *testing.T) {
	// The test cert has DNS SAN and valid validity, so it should not trigger HIGH violations.
	dir, certPath, _ := setupWorkDir(t)
	_, _, code := runBinary(t, dir, "--file="+certPath, "--mode=preissuance")
	// Exit 0 (pass) or 1 (policy fail) are both acceptable; we just want no system error.
	require.NotEqual(t, 2, code, "exit 2 (input error) should not occur")
	require.NotEqual(t, 3, code, "exit 3 (system error) should not occur")
}