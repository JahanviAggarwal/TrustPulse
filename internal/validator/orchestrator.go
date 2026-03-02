package validator

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/checks"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	zlintRes "github.com/zmap/zlint/v3/lint"
)

func RunAudit(filePath string, p *policy.Policy) (*policy.Report, error) {

	// 1️⃣ Read file
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// 2️⃣ Decode PEM
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	// 3️⃣ Build engine ONCE
	engine := policy.BuildEngine(p)

	var violations []policy.Violation
	var details string

	switch block.Type {

	// ==========================
	// CERTIFICATE FLOW
	// ==========================
	case "CERTIFICATE":

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		// 4️⃣ Run ZLint
		zlintResult := zlint.LintCertificate(cert)
		for name, res := range zlintResult.Results {
			if res.Status == zlintRes.Error || res.Status == zlintRes.Warn {

				// Default severity mapping: Error → HIGH, Warn → MEDIUM.
				// Operators can override individual lint names via the policy's
				// ZLintSeverityOverrides map.
				severity := policy.SeverityMedium
				if res.Status == zlintRes.Error {
					severity = policy.SeverityHigh
				}

				if override, ok := p.ZLintSeverityOverrides[name]; ok {
					severity = override
				}

				violations = append(violations, policy.Violation{
					RuleID:   "ZLINT-" + name,
					Severity: severity,
					Message:  res.Details,
					Standard: "ZLint",
				})
			}
		}

		// 5️⃣ Run your policy engine
		violations = append(violations, engine.EvaluateCert(cert, p)...)

		// 6️⃣ Collect details
		details = checks.GetCertificateDetails(cert)

	// ==========================
	// CSR FLOW
	// ==========================
	case "CERTIFICATE REQUEST":

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSR: %v", err)
		}

		// Run policy rules
		violations = append(violations, engine.EvaluateCSR(csr, p)...)

		csrDetails, err := checks.GetCSRDetails(csr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract CSR details: %v", err)
		}

		details = csrDetails.String()

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return &policy.Report{
		Violations: violations,
		Details:    details,
	}, nil
}