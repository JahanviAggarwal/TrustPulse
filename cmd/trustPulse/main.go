package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

// version is overridden at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// Exit codes: 0=pass, 1=policy violation, 2=input/usage error, 3=system error
	const (
		exitOK          = 0
		exitPolicyFail  = 1
		exitInputError  = 2
		exitSystemError = 3
	)

	modeFlag := flag.String("mode", "", "audit (default) or preissuance — exit 1 on violations matching fail_on")
	policyFlag := flag.String("policy", "", "path to YAML policy file (built-in defaults if omitted)")
	formatFlag := flag.String("format", "json", "output format: json (default) or text")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("trustpulse %s\n", version)
		os.Exit(exitOK)
	}

	format := *formatFlag
	if format != "json" && format != "text" {
		fmt.Fprintf(os.Stderr, "unknown format %q — must be 'json' or 'text'\n", format)
		os.Exit(exitInputError)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: trustpulse [--mode=audit|preissuance] [--policy=policy.yaml] [--format=json|text] <file>\n")
		os.Exit(exitInputError)
	}
	filePath := args[0]
	policyPath := *policyFlag

	var p *models.Policy
	var err error

	if policyPath != "" {
		p, err = policy.LoadPolicy(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load policy: %v\n", err)
			os.Exit(exitSystemError)
		}
		if format == "text" {
			fmt.Printf("Policy loaded: %s\n", policyPath)
		}
	} else {
		p = policy.DefaultPolicy()
	}

	// Determine effective run mode: CLI flag wins; fall back to policy file; then "audit".
	mode := *modeFlag
	if mode == "" {
		mode = p.Enforcement.Mode
	}
	if mode == "" {
		mode = "audit"
	}

	if format == "text" {
		fmt.Printf("Starting PKI Compliance Audit for: %s (mode=%s)\n", filePath, mode)
	}

	report, err := validator.RunAudit(filePath, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitSystemError)
	}

	// ─── Output ──────
	switch format {
	case "text":
		fmt.Println("\n--- AUDIT REPORT ---")
		fmt.Println(report.String())

	default: // "json"
		out, err := report.JSON(p, mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to serialise report: %v\n", err)
			os.Exit(exitSystemError)
		}
		fmt.Println(out)
	}

	if report.ShouldFail(p, mode) {
		if format == "text" {
			fmt.Println("Policy enforcement triggered. Blocking execution.")
		}
		os.Exit(exitPolicyFail)
	}

	if format == "text" {
		fmt.Println("\nResult: Audit complete.")
	}
}
