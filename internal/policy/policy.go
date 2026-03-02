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