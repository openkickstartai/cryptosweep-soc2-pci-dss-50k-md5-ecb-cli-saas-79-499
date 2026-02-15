# 🔐 CryptoSweep

**Cryptographic misuse & compliance scanner** — Find every MD5 hash, ECB cipher, hardcoded key, and disabled TLS check before your SOC2/PCI-DSS auditor does.

One CLI command. 10 languages. 4 compliance frameworks. Zero dependencies.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Scan a directory
python cryptosweep.py ./your-project

# PCI-DSS compliance report
python cryptosweep.py ./src --compliance PCI-DSS

# CI gate — fail build on critical findings
python cryptosweep.py ./src --fail-on critical

# SARIF output for GitHub Code Scanning
python cryptosweep.py ./src --format sarif > results.sarif

# JSON for automation
python cryptosweep.py ./src --format json
```

## 🔍 What It Detects

| ID | Finding | Severity | Frameworks |
|--------|-------------------------------|----------|------------------------|
| CS001 | MD5 hash usage | HIGH | PCI-DSS, SOC2, HIPAA |
| CS002 | SHA1 hash usage | HIGH | PCI-DSS, SOC2, FIPS |
| CS003 | ECB mode encryption | CRITICAL | PCI-DSS, SOC2 |
| CS004 | Hardcoded secrets/keys | CRITICAL | PCI-DSS, SOC2, HIPAA |
| CS005 | TLS verification disabled | CRITICAL | PCI-DSS, SOC2, HIPAA |
| CS006 | Insecure random generator | MEDIUM | PCI-DSS, SOC2 |
| CS007 | RSA key < 2048 bits | HIGH | PCI-DSS, FIPS, SOC2 |
| CS008 | DES/3DES usage | HIGH | PCI-DSS, FIPS |
| CS009 | Hardcoded IV/nonce | HIGH | PCI-DSS, SOC2 |
| CS010 | JWT 'none' algorithm | CRITICAL | PCI-DSS, SOC2 |

**Languages**: Python, JavaScript, TypeScript, Go, Java, C#, Ruby, PHP, Rust, Kotlin

## 💰 Pricing

| Feature | Free (OSS) | Pro $79/mo | Enterprise $499/mo |
|--------------------------------|------------|------------|--------------------|
| 10 core detection rules | ✅ | ✅ | ✅ |
| CLI scanning | ✅ | ✅ | ✅ |
| JSON + SARIF output | ✅ | ✅ | ✅ |
| CI gate (`--fail-on`) | ✅ | ✅ | ✅ |
| 50+ advanced rules | ❌ | ✅ | ✅ |
| PDF compliance reports | ❌ | ✅ | ✅ |
| GitHub/GitLab PR comments | ❌ | ✅ | ✅ |
| SOC2/PCI-DSS evidence export | ❌ | ✅ | ✅ |
| Custom rules engine | ❌ | ❌ | ✅ |
| Slack/Teams alerts | ❌ | ❌ | ✅ |
| SSO + team management | ❌ | ❌ | ✅ |
| Audit trail + history | ❌ | ❌ | ✅ |
| Priority support + SLA | ❌ | ❌ | ✅ |

## 📊 Why Pay for CryptoSweep?

**The cost of NOT scanning:**
- SOC2 audit remediation: **$20,000–$50,000**
- PCI-DSS non-compliance fine: **$5,000–$100,000/month**
- Average data breach (IBM 2023): **$4.45M**

**CryptoSweep Pro pays for itself after preventing ONE audit finding.**

### Who buys this?
- **Fintech** teams preparing for SOC2/PCI-DSS certification
- **Healthtech** startups needing HIPAA compliance evidence
- **Any B2B SaaS** facing enterprise security questionnaires

## 🔧 CI/CD Integration

```yaml
# GitHub Actions
- name: CryptoSweep
  run: python cryptosweep.py ./src --format sarif --fail-on high > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## 📄 License

BSL 1.1 — Free for teams ≤ 5 developers. Commercial license required for larger organizations.
