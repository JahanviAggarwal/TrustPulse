package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

func main() {
	// Default values
	mode := "audit"
	filePath := ""

	// Pre-scan os.Args to capture --mode anywhere and first non-flag as filePath
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--mode" && i+1 < len(os.Args):
			mode = os.Args[i+1]
			i++ // skip next
		case strings.HasPrefix(arg, "--mode="):
			mode = strings.SplitN(arg, "=", 2)[1]
		case !strings.HasPrefix(arg, "-") && filePath == "":
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Println("Usage: trustpulse [--mode=audit|preissuance] <file>")
		os.Exit(2)
	}

	fmt.Printf("Starting PKI Compliance Audit for: %s (mode=%s)\n", filePath, mode)

	report, err := validator.RunAudit(filePath)
	if err != nil {
		fmt.Printf("❌ SYSTEM ERROR: %v\n", err)
		os.Exit(1)
	}

	// Always print the audit report for visibility
	fmt.Println("\n--- AUDIT REPORT ---")
	fmt.Println(report.String())

	if mode == "preissuance" && report.HasBlockingViolations() {
		fmt.Println("❌ Blocking violations found. Guardrail triggered.")
		os.Exit(1) // blocks pipeline
	}

	if mode == "audit" || !report.HasBlockingViolations() {
		fmt.Println("\nResult: Audit complete.")
		if report.HasBlockingViolations() {
			fmt.Println("⚠️ Violations detected (HIGH severity), review recommended.")
		} else {
			fmt.Println("✅ No blocking violations. Certificate is compliant!")
		}
	}
}
