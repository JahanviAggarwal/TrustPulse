package validator

import (
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/checks"
	"github.com/JahanviAggarwal/TrustPulse/internal/parser"
	"github.com/JahanviAggarwal/TrustPulse/internal/report"

	"github.com/zmap/zlint/v3"
	zlintRes "github.com/zmap/zlint/v3/lint"
)

func RunAudit(certPath string) (string, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	cert, err := parser.ParsePEMCertificate(certBytes)
	if err != nil {
		return "", err
	}

	details := checks.GetCertificateDetails(cert)

	zlintResult := zlint.LintCertificate(cert)
	for name, res := range zlintResult.Results {
		switch res.Status {
		case zlintRes.Error:
			details += fmt.Sprintf("❌ [%s]: %s\n", name, res.Details)
		case zlintRes.Warn:
			details += fmt.Sprintf("⚠️ [%s]: %s\n", name, res.Details)
		}
	}

	finalReport := report.FormatReport(fmt.Sprintf("TrustPulse Audit: %s", certPath), details)
	return finalReport, nil
}
