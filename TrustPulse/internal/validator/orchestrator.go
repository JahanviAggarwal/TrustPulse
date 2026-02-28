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

func RunAudit(filePath string) (*policy.Report, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// Decode PEM
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var cert *x509.Certificate
	var csr *x509.CertificateRequest

	var errrCSR error
	var errrCert error

	// Check type
	switch block.Type {
	case "CERTIFICATE":
		var certErr error
		cert, certErr = x509.ParseCertificate(block.Bytes)
		errrCert = certErr
		if certErr != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", certErr)
		}
	case "CERTIFICATE REQUEST":
		var csrErr error
		csr, csrErr = x509.ParseCertificateRequest(block.Bytes) // pass raw bytes
		errrCSR = csrErr
		if csrErr != nil {
			return nil, fmt.Errorf("failed to parse CSR: %v", csrErr)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	engine := policy.NewEngine()
	policy.ApplyUniversalRules(engine)

	var violations []policy.Violation
	var details string

	switch block.Type {
	case "CERTIFICATE":
		// 1️⃣ Run zlint first
		zlintResult := zlint.LintCertificate(cert)
		for name, res := range zlintResult.Results {
			switch res.Status {
			case zlintRes.Error:
				violations = append(violations, policy.Violation{
					RuleID:   "ZLINT-" + name,
					Severity: policy.SeverityHigh,
					Message:  res.Details,
					Standard: "ZLint",
				})
			case zlintRes.Warn:
				violations = append(violations, policy.Violation{
					RuleID:   "ZLINT-" + name,
					Severity: policy.SeverityMedium,
					Message:  res.Details,
					Standard: "ZLint",
				})
			}
		}
		details = checks.GetCertificateDetails(cert)
		// Detect cert type
		isEV := policy.IsEV(cert)
		isSMIME := policy.IsSMIME(cert)
		isRootCA := cert.IsCA && cert.Subject.String() == cert.Issuer.String()

		// Apply policy rules
		if policy.IsTLSServer(cert) && !cert.IsCA {
			policy.ApplyTLSProfile(engine)
		}
		if isEV {
			policy.ApplyEVProfile(engine)
		}
		if isSMIME {
			policy.ApplySMIMEProfile(engine)
		}
		if cert.IsCA {
			policy.ApplyCAProfile(engine)
			if isRootCA {
				policy.ApplyRootCAProfile(engine)
			}
		}
		violations = append(violations, engine.EvaluateCert(cert)...)

	case "CERTIFICATE REQUEST":
		csrDetails, err := checks.GetCSRDetails(csr)
		if err != nil {
			return nil, fmt.Errorf("failed to get CSR details: %v", err)
		}
		policy.ApplyCSRRules(engine)

		details = "CSR Details:\n" + csrDetails.String() + "\n"

		// Apply only universal rules + any CSR-specific rules
		violations = append(violations, engine.EvaluateCSR(csr)...)
	default:
		return nil, fmt.Errorf("failed to parse certificate or CSR: %v, %v", errrCert, errrCSR)
	}

	return &policy.Report{
		Violations: violations,
		Details:    details,
	}, nil
}
