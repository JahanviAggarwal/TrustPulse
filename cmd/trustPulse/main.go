package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/JahanviAggarwal/TrustPulse/internal/models"
	"github.com/JahanviAggarwal/TrustPulse/internal/policy"
	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

func main() {
	mode := "audit"
	format := "json"
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
		fmt.Println("Usage: trustpulse [--mode=audit|preissuance] [--policy=policy.yml] [--format=json|text] <file>")
		os.Exit(2)
	}

	if format != "json" && format != "text" {
		fmt.Fprintf(os.Stderr, "unknown format %q — use 'json' or 'text'\n", format)
		os.Exit(2)
	}

	var (
		p   *models.Policy
		err error
	)

	if policyPath != "" {
		p, err = policy.LoadPolicy(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load policy: %v\n", err)
			os.Exit(1)
		}
	} else {
		p = policy.DefaultPolicy()
	}

	if format == "text" {
		fmt.Printf("TrustPulse — auditing %s (mode=%s)\n", filePath, mode)
	}

	report, err := validator.RunAudit(filePath, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch format {
	case "text":
		fmt.Println(report.String())

	default:
		out, err := report.JSON(p, mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to serialize report: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(out)
	}

	if report.ShouldFail(p, mode) {
		if format == "text" {
			fmt.Fprintln(os.Stderr, "policy enforcement triggered — exiting non-zero")
		}

		os.Exit(1)
	}
}