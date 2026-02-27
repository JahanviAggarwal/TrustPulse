package parser

import (
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

func ParsePEMCertificate(pemBytes []byte) (*x509.Certificate, error) {
	cleaned := []byte(strings.TrimSpace(string(pemBytes)))

	var block *pem.Block
	rest := cleaned
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no valid CERTIFICATE block found")
		}
		if strings.EqualFold(block.Type, "CERTIFICATE") {
			break
		}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}