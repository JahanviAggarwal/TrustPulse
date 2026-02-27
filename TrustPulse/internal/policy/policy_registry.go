package policy

func ApplyTLSProfile(engine *Engine) {
	engine.Register(RuleMaxValidity)
	engine.Register(RuleSANRequired)
	engine.Register(RuleCNMatchesSAN)
	engine.Register(RuleRevocationInfo)
	engine.Register(RuleInternalIPSAN)
}

func ApplyEVProfile(engine *Engine) {
	engine.Register(RuleEVOrganizationPresent)
	engine.Register(RuleEVBusinessCategory)
	engine.Register(RuleEVCountryPresent)
	engine.Register(RuleEVMustBeTLS)
}

func ApplySMIMEProfile(engine *Engine) {
	engine.Register(RuleSMIMEKeyUsage)
	engine.Register(RuleSMIMEEKU)
	engine.Register(RuleSMIMESAN)
	engine.Register(RuleSMIMERevocation)
}

func ApplyRootCAProfile(engine *Engine) {
	engine.Register(RuleRootSelfSigned)
	engine.Register(RuleRootKeySize)
}

func ApplyCAProfile(engine *Engine) {
	engine.Register(RuleCAKeyUsage)
}

func ApplyUniversalRules(engine *Engine) {
	engine.Register(RuleNoSHA1)
	engine.Register(RuleMinRSAKeySize)
	engine.Register(RulePQCKeySize)
}
