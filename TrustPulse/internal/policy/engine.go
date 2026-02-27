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

func (e *Engine) Evaluate(cert *zcrypto.Certificate) []Violation {
	var violations []Violation

	for _, rule := range e.rules {
		if v := rule(cert); v != nil {
			violations = append(violations, *v)
		}
	}

	return violations
}