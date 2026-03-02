> # TrustPulse

**TrustPulse** is a PKI compliance validator for X.509 certificates and Certificate Signing Requests (CSRs), written in Go. It translates CA/Browser Forum standards, RFC 5280, and Root Program policies into executable policy-as-code guardrails — catching non-compliance before issuance and during audits.

> ⚡ **Status: Active Development**

---

## Features

| Category | Details |
|---|---|
| **CA/B Forum Baseline Requirements** | TLS SAN enforcement, max 398-day validity, minimum RSA key size (BR §7.1.4.2.1) |
| **ECDSA curve enforcement** | Minimum ECDSA curve bit-strength for certificates, CSRs, and Root CAs (rejects P-192/P-224) |
| **EV Guidelines** | Organization, Country, BusinessCategory subject fields; required EKUs |
| **S/MIME Baseline Requirements** | EKU, email SAN, digitalSignature KeyUsage, OCSP/CRL revocation info |
| **Root Program Policies** | Self-signed enforcement, keyCertSign KeyUsage, minimum RSA/ECDSA key size |
| **RFC 5280** | CA KeyUsage (§4.2.1.3), SAN extension requirements |
| **Post-Quantum Cryptography (PQC)** | OID allowlist/denylist for NIST PQC algorithms (ML-KEM/Kyber) |
| **zlint integration** | Configurable — enable/disable and reclassify individual lint severities via policy YAML |
| **ASN.1 URI SAN extraction** | Manually parses `GeneralName` sequences to extract URI SANs from CSRs |
| **Pre-issuance enforcement** | `--mode=preissuance` exits **1** (policy violation), **2** (input error), or **3** (system error) — a drop-in CI/CD gate |
| **Policy-as-code** | All rules driven by a human-readable YAML policy file |
| **JSON & text output** | Machine-readable JSON (default) or human-readable text via `--format=text` |

---

## Architecture

```
TrustPulse/
├── cmd/trustPulse/
│   ├── main.go               # CLI entry point — flag parsing, output routing
│   └── configs/
│       └── policy.yml        # Default policy configuration
└── internal/
    ├── policy/
    │   ├── engine.go         # Rule engine — registers and evaluates rules
    │   ├── policy.go         # Policy struct, YAML loader, DefaultPolicy()
    │   ├── types.go          # Violation, Report, Summary, JSON/text output
    │   ├── ca_b_br.go        # CA/B Forum BR rules (TLS, universal cert/CSR)
    │   ├── ev.go             # EV Guidelines rules
    │   ├── smime.go          # S/MIME BR rules
    │   └── root.go           # Root Program policy rules
    ├── validator/
    │   └── orchestrator.go   # Routes PEM input (cert vs CSR), runs zlint + engine
    └── checks/
        └── compliance.go     # Certificate/CSR detail extraction, ASN.1 URI SAN parser
```

### How it works

1. **Input** — a PEM file (certificate or CSR) is passed on the command line.
2. **Orchestrator** decodes the PEM and routes it to the certificate or CSR validation path.
3. **zlint** runs the full BR lint suite on certificates.
4. **Policy Engine** evaluates all registered `Rule` implementations against the loaded policy.
5. **Report** aggregates violations with rule IDs, standards references, and severity levels.
6. **Output** is printed as JSON (default) or text; the process exits non-zero if enforcement mode triggers.

---

## Installation

```bash
go install github.com/JahanviAggarwal/TrustPulse/cmd/trustPulse@latest
```

Or build from source:

```bash
git clone https://github.com/JahanviAggarwal/TrustPulse.git
cd TrustPulse/TrustPulse
go build -o trustpulse ./cmd/trustPulse
```

---

## Usage

### Audit a certificate (JSON output, default)

```bash
./trustpulse cert.pem
```

### Audit a certificate (human-readable text)

```bash
./trustpulse --format=text cert.pem
```

### Validate a CSR before issuance (blocks on HIGH violations)

```bash
./trustpulse --mode=preissuance --policy=policy.yml csr.pem
```

### Use a custom policy file

```bash
./trustpulse --policy=configs/policy.yml cert.pem
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `audit` | `audit` (report only) or `preissuance` (exit 1 on violations matching `fail_on`) |
| `--policy` | built-in defaults | Path to a YAML policy file |
| `--format` | `json` | `json` (machine-readable) or `text` (human-readable) |

---

## Example JSON Output

```json
{
  "summary": {
    "total": 3,
    "high": 2,
    "medium": 1,
    "low": 0,
    "passed": false
  },
  "violations": [
    {
      "rule_id": "ZLINT-e_sub_cert_cert_policy_empty",
      "standard": "ZLint",
      "severity": "HIGH",
      "message": "Certificate policy extension is empty"
    },
    {
      "rule_id": "TLS-SAN-001",
      "standard": "CA/B Forum BR 7.1.4.2.1",
      "severity": "HIGH",
      "message": "TLS certificate must contain DNS or IP SAN"
    },
    {
      "rule_id": "CERT-VAL-001",
      "standard": "Certificate Policy",
      "severity": "MEDIUM",
      "message": "Certificate validity exceeds policy maximum"
    }
  ]
}
```

---

## Policy Configuration

TrustPulse is fully driven by a YAML policy file. All rules are no-ops unless enabled:

```yaml
version: "1.0"

# Universal certificate checks
certificate:
  min_rsa_key_size: 2048         # Minimum RSA key size in bits
  max_validity_days: 398         # CA/B Forum BR maximum (398 days)
  allowed_signature_algorithms:
    - SHA256-RSA
    - ECDSA-SHA256
  require_san: true

  # Post-Quantum Cryptography
  enable_pqc_checks: true
  allowed_pqc_oids:
    - "2.16.840.1.101.3.4.1.56"  # ML-KEM-768
    - "2.16.840.1.101.3.4.1.57"  # ML-KEM-1024
  disallow_low_security_pqc: true # Blocks ML-KEM-512

# Pre-issuance CSR checks
csr:
  min_rsa_key_size: 2048
  allowed_signature_algorithms:
    - SHA256-RSA
    - ECDSA-SHA256
  require_san: true

# Enforcement behaviour
enforcement:
  mode: "audit"          # audit | preissuance
  fail_on: ["HIGH"]      # Severity levels that trigger exit 1 in preissuance mode

# Extended Validation
ev:
  enabled: true
  required_subject_fields:
    organization: true
    country: true
    business_category: true
  required_ekus:
    - 1  # serverAuth

# S/MIME Baseline Requirements
smime:
  enabled: true
  require_eku:
    - 4  # emailProtection
  require_email: true
  require_revocation: true
  require_digital_signature: true

# TLS Server profile
tls_server:
  require_san: true

# Root CA policy
root:
  enabled: true
  min_rsa_key_size: 4096
  require_self_signed: true
  require_key_usage_cert_sign: true
```

---

## Supported Standards & Rule IDs

| Standard | Rule IDs | Source File |
|---|---|---|
| CA/B Forum Baseline Requirements | `TLS-SAN-001`, `TLS-CSR-SAN-001`, `CERT-KEY-001`, `CERT-SIG-001`, `CERT-VAL-001`, `CERT-SAN-001` | `ca_b_br.go` |
| CA/B Forum EV Guidelines | `EV-ORG-MISSING`, `EV-COUNTRY-MISSING`, `EV-BUSINESS-CATEGORY-MISSING`, `EV-EKU-MISSING` | `ev.go` |
| CA/B Forum S/MIME BRs | `SMIME-EKU-MISSING`, `SMIME-SAN-MISSING`, `SMIME-KEYUSAGE-MISSING`, `SMIME-KEYUSAGE-INVALID`, `SMIME-REVOCATION-MISSING` | `smime.go` |
| RFC 5280 / Root Program | `ROOT-NOT-SELF-SIGNED`, `ROOT-KEY-SIZE`, `RFC5280-CA-KEYUSAGE`, `CSR-ROOT-KEY-001` | `root.go` |
| NIST PQC | `RFC5280-PQC-NOT-ALLOWED`, `RFC5280-PQC-LOW-SECURITY` | `ca_b_br.go` |
| Pre-issuance (CSR) | `CSR-KEY-001`, `CSR-SIG-001`, `CSR-SAN-001` | `ca_b_br.go` |
| zlint (full BR suite) | `ZLINT-*` (all zlint lint names prefixed) | `orchestrator.go` |