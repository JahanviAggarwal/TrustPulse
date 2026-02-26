package report

import "fmt"

func FormatReport(header string, body string) string {
	return fmt.Sprintf("--- %s ---\n%s\n----------------------\n", header, body)
}
