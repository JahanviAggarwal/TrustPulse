package policy

import (
	"os"

	zcrypto "github.com/zmap/zcrypto/x509"
	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version     string            `yaml:"version"`
	CSR         CSRPolicy         `yaml:"csr"`
	Certificate CertificatePolicy `yaml:"certificate"`
	Enforcement EnforcementPolicy `yaml:"enforcement"`
	EV          EVPolicy          `yaml:"ev"`
	SMIME       SMIMEPolicy       `yaml:"smime"`
	TLSServer   TLSServerPolicy   `yaml:"tls_server"`
	Root        RootPolicy        `yaml:"root"`
}

type RootPolicy struct {
	Enabled                 bool  `yaml:"enabled"`                 // Enable/disable root-specific checks
	MinRSAKeySize           int   `yaml:"min_rsa_key_size"`       // Minimum key size for root CA
	RequireSelfSigned       bool  `yaml:"require_self_signed"`     // Root CA must be self-signed
	RequireKeyUsageCertSign bool  `yaml:"require_key_usage_cert_sign"` // KeyUsage must include keyCertSign
}

type CSRPolicy struct {
	MinRSAKeySize              int      `yaml:"min_rsa_key_size"`
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms"`
	RequireSAN                 bool     `yaml:"require_san"`
}

type CertificatePolicy struct {
	MaxValidityDays            int      `yaml:"max_validity_days"`
	MinRSAKeySize              int      `yaml:"min_rsa_key_size"`
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms"`
	RequireSAN                 bool     `yaml:"require_san"`

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

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Policy
	err = yaml.Unmarshal(data, &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func DefaultPolicy() *Policy {
	return &Policy{
		Version: "1.0",
		CSR: CSRPolicy{
			MinRSAKeySize:              2048,
			RequireSAN:                 true,
			AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
		},
		Certificate: CertificatePolicy{
			MinRSAKeySize:              2048,
			MaxValidityDays:            398,
			RequireSAN:                 true,
			AllowedSignatureAlgorithms: []string{"SHA256-RSA", "ECDSA-SHA256"},
		},
		Enforcement: EnforcementPolicy{
			Mode:   "audit",
			FailOn: []Severity{"HIGH"},
		},
	}
}
