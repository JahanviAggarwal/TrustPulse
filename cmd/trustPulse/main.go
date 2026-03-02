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
	format := "json" // default output format; use --format=text for human-readable
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
		case strings.HasPrefix(arg, "--policy="):
			policyPath = strings.SplitN(arg, "=", 2)[1]

		case arg == "--format" && i+1 < len(os.Args):
			format = os.Args[i+1]
			i++

		case strings.HasPrefix(arg, "--format="):
			format = strings.SplitN(arg, "=", 2)[1]

		case !strings.HasPrefix(arg, "-") && filePath == "":
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Println("Usage: trustpulse [--mode=audit|preissuance] [--policy=policy.yaml] [--format=json|text] <file>")
		os.Exit(2)
	}

	if format != "json" && format != "text" {
		fmt.Fprintf(os.Stderr, "❌ Unknown format %q — must be 'json' or 'text'\n", format)
		os.Exit(2)
	}

	// 🔐 Load Policy
	var p *policy.Policy
	var err error

	if policyPath != "" {
		p, err = policy.LoadPolicy(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load policy: %v\n", err)
			os.Exit(1)
		}
		if format == "text" {
			fmt.Println("✅ Policy loaded successfully:")
			fmt.Printf("%+v\n", p.SMIME)
		}
	} else {
		p = policy.DefaultPolicy()
	}

	if format == "text" {
		fmt.Printf("Starting PKI Compliance Audit for: %s (mode=%s)\n", filePath, mode)
	}

	report, err := validator.RunAudit(filePath, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ SYSTEM ERROR: %v\n", err)
		os.Exit(1)
	}

	// ─── Output ──────
	switch format {
	case "text":
		fmt.Println("\n--- AUDIT REPORT ---")
		fmt.Println(report.String())

	default: // "json"
		out, err := report.JSON(p, mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to serialise report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(out)
	}

	// 🔥 Policy-driven enforcement (applies regardless of output format)
	if report.ShouldFail(p, mode) {
		if format == "text" {
			fmt.Println("❌ Policy enforcement triggered. Blocking execution.")
		}
		os.Exit(1)
	}

	if format == "text" {
		fmt.Println("\nResult: Audit complete.")
	}
}