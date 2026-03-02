package validator

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/checks"
	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	zlintRes "github.com/zmap/zlint/v3/lint"
)

func RunAudit(filePath string, p *models.Policy) (*models.Report, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	engine := policy.BuildEngine(p)

	var violations []models.Violation
	var details string

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		// Run zlint only when enabled in policy. When disabled, TrustPulse's
		// own rules still run — operators can opt out of the full BR lint suite
		// without losing their custom policy checks.
		if p.ZLint.Enabled {
			zlintResult := zlint.LintCertificate(cert)
			for name, res := range zlintResult.Results {
				if res.Status != zlintRes.Error && res.Status != zlintRes.Warn {
					continue
				}

				// Default mapping: Error→HIGH, Warn→MEDIUM.
				// Per-lint overrides can remap individual results via policy.
				severity := models.SeverityMedium
				if res.Status == zlintRes.Error {
					severity = models.SeverityHigh
				}

				if override, ok := p.ZLint.SeverityOverrides[name]; ok {
					severity = override
				}
				violations = append(violations, models.Violation{
					RuleID:   "ZLINT-" + name,
					Severity: severity,
					Message:  res.Details,
					Standard: "ZLint",
				})
			}
		}

		violations = append(violations, engine.EvaluateCert(cert, p)...)
		details = checks.GetCertificateDetails(cert)

	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSR: %v", err)
		}
		violations = append(violations, engine.EvaluateCSR(csr, p)...)
		csrDetails, err := checks.GetCSRDetails(csr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract CSR details: %v", err)
		}
		details = csrDetails.String()

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return &models.Report{
		Violations: violations,
		Details:    details,
	}, nil
}