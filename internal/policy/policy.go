package policy

import (
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"gopkg.in/yaml.v3"
)

func LoadPolicy(path string) (*models.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p models.Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func DefaultPolicy() *models.Policy {
	return &models.Policy{
		Version: "1.0",
		ZLint: models.ZLintPolicy{
			Enabled: true,
		},
		CSR: models.CSRPolicy{
			MinRSAKeySize:              2048,
			RequireSAN:                 true,
			AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
		},
		Certificate: models.CertificatePolicy{
			MinRSAKeySize:              2048,
			MaxValidityDays:            398,
			RequireSAN:                 true,
			AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
		},
		Enforcement: models.EnforcementPolicy{
			Mode:   "audit",
			FailOn: []models.Severity{"HIGH"},
		},
	}
}