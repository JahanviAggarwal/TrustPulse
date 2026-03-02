package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

// set via -ldflags at build time
var version = "dev"

func main() {
	const (
		exitOK          = 0
		exitPolicyFail  = 1
		exitInputError  = 2
		exitSystemError = 3
	)

	fileFlag := flag.String("file", "", "path to PEM file (certificate or CSR) to audit [required]")
	modeFlag := flag.String("mode", "", "audit (default) or preissuance — exit 1 on violations matching fail_on")
	policyFlag := flag.String("policy", "", "path to YAML policy file (auto-detects policy.yaml/policy.yml in current directory if omitted)")
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

	filePath := *fileFlag
	if filePath == "" {
		fmt.Fprintf(os.Stderr, "error: --file is required\n")
		fmt.Fprintf(os.Stderr, "Usage: trustpulse --file=<pem> [--mode=audit|preissuance] [--policy=policy.yaml] [--format=json|text]\n")
		os.Exit(exitInputError)
	}

	policyPath := *policyFlag
	if policyPath == "" {
		for _, name := range []string{"policy.yaml", "policy.yml"} {
			if _, err := os.Stat(name); err == nil {
				policyPath = name
				break
			}
		}
	}
	if policyPath == "" {
		fmt.Fprintf(os.Stderr, "error: no policy file found\n")
		fmt.Fprintf(os.Stderr, "Use --policy=<path> or place a 'policy.yaml' in the current directory.\n")
		os.Exit(exitInputError)
	}

	p, err := policy.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policy %q: %v\n", policyPath, err)
		os.Exit(exitSystemError)
	}
	if format == "text" {
		fmt.Printf("Policy loaded: %s\n", policyPath)
	}

	// flag wins; fall back to what's in the policy file, then default to audit
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

	switch format {
	case "text":
		fmt.Println("\n--- AUDIT REPORT ---")
		fmt.Println(report.String())
	default:
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