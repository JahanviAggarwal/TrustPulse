package validator

import (
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/checks"
	"github.com/JahanviAggarwal/TrustPulse/internal/parser"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
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

	isEV := policy.IsEV(cert)
	isSMIME := policy.IsSMIME(cert)
	isRootCA := cert.IsCA && cert.Subject.String() == cert.Issuer.String()

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

	// Run Policy-as-Code rules
	engine := policy.NewEngine()

	// Rules applied to all type of cert
	policy.ApplyUniversalRules(engine)
	if policy.IsTLSServer(cert) && !cert.IsCA {
		policy.ApplyTLSProfile(engine)
	}
	if isEV {
		policy.ApplyEVProfile(engine)
	}
	if isSMIME {
		fmt.Println("Applying S/MIME specific rules...")
		policy.ApplySMIMEProfile(engine)
	}
	if cert.IsCA {
		// CA-wide rules
		policy.ApplyCAProfile(engine)
		if isRootCA {
			policy.ApplyRootCAProfile(engine)
		}
	}

	violations := engine.Evaluate(cert)

	if len(violations) == 0 {
		details += "✅ No policy violations found.\n"
	} else {
		// Append policy violations to details
		for _, v := range violations {
			switch v.Severity {
			case policy.SeverityHigh:
				details += fmt.Sprintf("❌ [%s]: %s (%s)\n", v.RuleID, v.Message, v.Standard)
			case policy.SeverityMedium, policy.SeverityLow:
				details += fmt.Sprintf("⚠️ [%s]: %s (%s)\n", v.RuleID, v.Message, v.Standard)
			}
		}
	}

	// 6. Final formatted report
	finalReport := report.FormatReport(fmt.Sprintf("TrustPulse Audit: %s", certPath), details)
	return finalReport, nil
}
