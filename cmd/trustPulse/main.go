package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

func main() {
	mode := "audit"
	filePath := ""
	policyPath := ""

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch {
		case arg == "--mode" && i+1 < len(os.Args):
			mode = os.Args[i+1]
			i++

		case strings.HasPrefix(arg, "--mode="):
			mode = strings.SplitN(arg, "=", 2)[1]
		case arg == "--policy" && i+1 < len(os.Args):
			policyPath = os.Args[i+1]
			i++

		case !strings.HasPrefix(arg, "-") && filePath == "":
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Println("Usage: trustpulse [--mode=audit|preissuance] [--policy=policy.yaml] <file>")
		os.Exit(2)
	}

	// 🔐 Load Policy
	var p *policy.Policy
	var err error

	if policyPath != "" {
		p, err = policy.LoadPolicy(policyPath)
		if err != nil {
			fmt.Printf("❌ Failed to load policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Policy loaded successfully:")
		fmt.Printf("%+v\n", p.SMIME)
	} else {
		p = policy.DefaultPolicy()
	}

	fmt.Printf("Starting PKI Compliance Audit for: %s (mode=%s)\n", filePath, mode)

	report, err := validator.RunAudit(filePath, p)
	if err != nil {
		fmt.Printf("❌ SYSTEM ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n--- AUDIT REPORT ---")
	fmt.Println(report.String())

	// 🔥 Policy-driven enforcement
	if report.ShouldFail(p, mode) {
		fmt.Println("❌ Policy enforcement triggered. Blocking execution.")
		os.Exit(1)
	}

	fmt.Println("\nResult: Audit complete.")
}
