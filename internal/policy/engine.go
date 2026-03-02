package policy

import (
	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	zcrypto "github.com/zmap/zcrypto/x509"
)

type Engine struct {
	rules []models.Rule
}

func NewEngine() *Engine {
	return &Engine{rules: []models.Rule{}}
}

func (e *Engine) Register(rule models.Rule) {
	e.rules = append(e.rules, rule)
}

func (e *Engine) EvaluateCert(cert *zcrypto.Certificate, p *models.Policy) []models.Violation {
	var violations []models.Violation

	for _, rule := range e.rules {
		for _, v := range rule.ValidateCert(cert, p) {
			violations = append(violations, *v)
		}
	}

	return violations
}

func (e *Engine) EvaluateCSR(csr *zcrypto.CertificateRequest, p *models.Policy) []models.Violation {
	var violations []models.Violation

	for _, rule := range e.rules {
		for _, v := range rule.ValidateCSR(csr, p) {
			violations = append(violations, *v)
		}
	}

	return violations
}

func BuildEngine(p *models.Policy) *Engine {
	engine := NewEngine()

	engine.Register(&RuleUniversalCert{Policy: &p.Certificate})
	engine.Register(&RuleUniversalCSR{Policy: &p.CSR})
	engine.Register(&RuleTLSServerCert{Policy: &p.TLSServer})
	engine.Register(&RuleSMIME{Policy: &p.SMIME})
	engine.Register(&RuleEV{Policy: &p.EV})
	engine.Register(&RuleRoot{Policy: &p.Root})

	return engine
}