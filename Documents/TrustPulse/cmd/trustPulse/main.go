package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/JahanviAggarwal/TrustPulse/internal/validator"
)

func main() {
	// Check if the user provided a certificate file path
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/trustPulse/main.go <path-to-cert.pem>")
		return
	}

	certPath := os.Args[1]
	fmt.Printf("Starting PKI Compliance Audit for: %s\n", certPath)

	// Execute the audit logic
	report, err := validator.RunAudit(certPath)

	// 1. Handle system errors (file missing, bad format)
	if err != nil {
		fmt.Printf("❌ SYSTEM ERROR: %v\n", err)
		os.Exit(1)
	}

	// 2. Output the detailed report
	fmt.Println("\n--- AUDIT REPORT ---")
	fmt.Println(report)

	// 3. Final summary logic for the terminal
	if strings.Contains(report, "❌") || strings.Contains(report, "⚠️") {
		fmt.Println("Result: Audit complete. Security issues were identified.")
	} else {
		fmt.Println("Result: Audit complete. Certificate is compliant!")
	}
}
