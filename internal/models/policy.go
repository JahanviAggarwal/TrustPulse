package models

import (
	zcrypto "github.com/zmap/zcrypto/x509"
)

// ZLintPolicy controls the embedded zlint BR lint suite.
type ZLintPolicy struct {
	// Enabled controls whether zlint runs on certificates (default: true).
	Enabled bool `yaml:"enabled"`
	// SeverityOverrides lets operators reclassify individual lint results.
	// Keys are the raw lint name (e.g. "e_sub_cert_cert_policy_empty");
	// values are "HIGH", "MEDIUM", or "LOW".
	// Results not listed here use the default mapping (Error→HIGH, Warn→MEDIUM).
	SeverityOverrides map[string]Severity `yaml:"severity_overrides"`
}

type Policy struct {
	Version     string            `yaml:"version"`
	CSR         CSRPolicy         `yaml:"csr"`
	Certificate CertificatePolicy `yaml:"certificate"`
	Enforcement EnforcementPolicy `yaml:"enforcement"`
	EV          EVPolicy          `yaml:"ev"`
	SMIME       SMIMEPolicy       `yaml:"smime"`
	TLSServer   TLSServerPolicy   `yaml:"tls_server"`
	Root        RootPolicy        `yaml:"root"`
	ZLint       ZLintPolicy       `yaml:"zlint"`
}

type RootPolicy struct {
	Enabled       bool `yaml:"enabled"`
	MinRSAKeySize int  `yaml:"min_rsa_key_size"`
	// MinECDSACurveBits enforces a minimum ECDSA curve size for root CAs (0 = disabled).
	MinECDSACurveBits       int  `yaml:"min_ecdsa_curve_bits"`
	RequireSelfSigned       bool `yaml:"require_self_signed"`
	RequireKeyUsageCertSign bool `yaml:"require_key_usage_cert_sign"`
}

type CSRPolicy struct {
	MinRSAKeySize int `yaml:"min_rsa_key_size"`
	// MinECDSACurveBits enforces a minimum ECDSA curve size for CSR keys (0 = disabled).
	MinECDSACurveBits          int      `yaml:"min_ecdsa_curve_bits"`
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms"`
	RequireSAN                 bool     `yaml:"require_san"`
}

type CertificatePolicy struct {
	MaxValidityDays            int      `yaml:"max_validity_days"`
	MinRSAKeySize              int      `yaml:"min_rsa_key_size"`
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms"`
	RequireSAN                 bool     `yaml:"require_san"`

	// MinECDSACurveBits enforces a minimum ECDSA curve security level.
	// Set to 256 to reject P-192 and P-224; set to 384 to also reject P-256.
	// Zero disables the check.
	MinECDSACurveBits int `yaml:"min_ecdsa_curve_bits"`

	EnablePQCChecks        bool     `yaml:"enable_pqc_checks"`
	DisallowLowSecurityPQC bool     `yaml:"disallow_low_security_pqc"`
	AllowedPQCOIDs         []string `yaml:"allowed_pqc_oids"`
}

type EnforcementPolicy struct {
	Mode   string     `yaml:"mode"`    // strict-preissuance | audit
	FailOn []Severity `yaml:"fail_on"` // HIGH, MEDIUM
}

type EVPolicy struct {
	Enabled bool `yaml:"enabled"`

	RequiredSubjectFields struct {
		Organization     bool `yaml:"organization"`
		Country          bool `yaml:"country"`
		BusinessCategory bool `yaml:"business_category"`
	}

	RequiredEKUs []zcrypto.ExtKeyUsage `yaml:"required_ekus"`
}

type SMIMEPolicy struct {
	Enabled                 bool                  `yaml:"enabled"`
	RequireEKU              []zcrypto.ExtKeyUsage `yaml:"require_eku"`
	RequireEmail            bool                  `yaml:"require_email"`
	RequireRevocation       bool                  `yaml:"require_revocation"`
	RequireDigitalSignature bool                  `yaml:"require_digital_signature"`
}

type TLSServerPolicy struct {
	RequireSAN bool `yaml:"require_san"`
}
