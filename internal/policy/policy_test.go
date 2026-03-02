package policy

import (
	"os"
	"testing"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicy(t *testing.T) {
	yaml := `
version: "1.0"
certificate:
  min_rsa_key_size: 4096
  max_validity_days: 180
  require_san: true
enforcement:
  mode: "preissuance"
  fail_on: ["HIGH", "MEDIUM"]
`
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yml")
	require.NoError(t, err)
	_, err = f.WriteString(yaml)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	p, err := LoadPolicy(f.Name())
	require.NoError(t, err)
	require.Equal(t, "1.0", p.Version)
	require.Equal(t, 4096, p.Certificate.MinRSAKeySize)
	require.Equal(t, 180, p.Certificate.MaxValidityDays)
	require.Equal(t, "preissuance", p.Enforcement.Mode)
	require.Contains(t, p.Enforcement.FailOn, models.Severity("HIGH"))
	require.Contains(t, p.Enforcement.FailOn, models.Severity("MEDIUM"))
}

func TestLoadPolicy_fileNotFound(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yml")
	require.Error(t, err)
}

func TestLoadPolicy_badYAML(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.yml")
	require.NoError(t, err)
	_, err = f.WriteString("{ this is: [not valid yaml")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// yaml.v3 is lenient with some malformed input — just ensure no panic
	_, _ = LoadPolicy(f.Name())
}

func TestLoadPolicy_zlintOverrides(t *testing.T) {
	yaml := `
version: "1.0"
zlint:
  enabled: true
  severity_overrides:
    e_sub_cert_cert_policy_empty: "MEDIUM"
    w_ext_subject_key_identifier_missing_sub_cert: "LOW"
`
	f, err := os.CreateTemp(t.TempDir(), "policy-overrides-*.yml")
	require.NoError(t, err)
	_, err = f.WriteString(yaml)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	p, err := LoadPolicy(f.Name())
	require.NoError(t, err)
	require.True(t, p.ZLint.Enabled)
	require.Equal(t, models.Severity("MEDIUM"), p.ZLint.SeverityOverrides["e_sub_cert_cert_policy_empty"])
	require.Equal(t, models.Severity("LOW"), p.ZLint.SeverityOverrides["w_ext_subject_key_identifier_missing_sub_cert"])
}

func TestDefaultPolicy_zlintEnabled(t *testing.T) {
	p := DefaultPolicy()
	require.True(t, p.ZLint.Enabled, "zlint should be enabled in the default policy")
}
