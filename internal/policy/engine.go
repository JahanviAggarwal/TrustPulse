package policy

import zcrypto "github.com/zmap/zcrypto/x509"

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		rules: []Rule{},
	}
}

func (e *Engine) Register(rule Rule) {
	e.rules = append(e.rules, rule)
}

func (e *Engine) EvaluateCert(cert *zcrypto.Certificate, p *Policy) []Violation {
	var violations []Violation
	for _, rule := range e.rules {
		vs := rule.ValidateCert(cert, p)
		for _, v := range vs {
			violations = append(violations, *v)
		}
	}
	return violations
}
func (e *Engine) EvaluateCSR(csr *zcrypto.CertificateRequest, p *Policy) []Violation {
	var violations []Violation

	for _, rule := range e.rules {
		vs := rule.ValidateCSR(csr, p)
		for _, v := range vs {
			violations = append(violations, *v)
		}
	}

	return violations
}

func BuildEngine(policy *Policy) *Engine {
	engine := NewEngine()

	// Universal rules (always apply)
	engine.Register(&RuleUniversalCert{Policy: &policy.Certificate})
	engine.Register(&RuleUniversalCSR{Policy: &policy.CSR})

	// TLS-specific rules
	engine.Register(&RuleTLSServerCert{Policy: &policy.TLSServer})

	// Optional feature-based rules
	engine.Register(&RuleSMIME{Policy: &policy.SMIME})
	engine.Register(&RuleEV{Policy: &policy.EV})
	engine.Register(&RuleRoot{Policy: &policy.Root})

	return engine
}
