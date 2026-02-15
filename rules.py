"""CryptoSweep detection rules — cryptographic misuse patterns across languages."""

RULES = [
    {
        "id": "CS001", "name": "MD5 hash usage", "severity": "HIGH",
        "pattern": r"(?i)(hashlib\.md5|MD5\.Create|getInstance\(\s*[\"']MD5|crypto/md5|createHash\([\"']md5)",
        "compliance": ["PCI-DSS-3.4", "SOC2-CC6.1", "HIPAA-164.312"],
        "fix": "Use SHA-256+ for integrity, bcrypt/argon2 for passwords"
    },
    {
        "id": "CS002", "name": "SHA1 hash usage", "severity": "HIGH",
        "pattern": r"(?i)(hashlib\.sha1|SHA1\.Create|getInstance\([\"']SHA-?1|crypto/sha1|createHash\([\"']sha1)",
        "compliance": ["PCI-DSS-3.4", "SOC2-CC6.1", "FIPS-140-2"],
        "fix": "Use SHA-256 or SHA-3 instead"
    },
    {
        "id": "CS003", "name": "ECB mode encryption", "severity": "CRITICAL",
        "pattern": r"(?i)(AES/ECB|MODE_ECB|ECB_MODE|CipherMode\.ECB|\"ecb\")",
        "compliance": ["PCI-DSS-3.4", "SOC2-CC6.1"],
        "fix": "Use AES-GCM or AES-CBC with HMAC instead of ECB"
    },
    {
        "id": "CS004", "name": "Hardcoded secret or key", "severity": "CRITICAL",
        "pattern": r"(?i)(?:password|passwd|secret|api_key|apikey|auth_token|private_key|secret_key)\s*=\s*[\"'][^\"']{6,}[\"']",
        "compliance": ["PCI-DSS-2.3", "SOC2-CC6.1", "HIPAA-164.312"],
        "fix": "Use environment variables or a secrets manager (Vault, AWS Secrets Manager)"
    },
    {
        "id": "CS005", "name": "TLS verification disabled", "severity": "CRITICAL",
        "pattern": r"(?i)(verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CERT_NONE|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0)",
        "compliance": ["PCI-DSS-4.1", "SOC2-CC6.7", "HIPAA-164.312"],
        "fix": "Always verify TLS certificates. Use proper CA bundles."
    },
    {
        "id": "CS006", "name": "Insecure random generator", "severity": "MEDIUM",
        "pattern": r"(?i)(\brandom\.random\(|\brandom\.randint\(|Math\.random\(\)|rand\.Intn\(|java\.util\.Random\b)",
        "compliance": ["PCI-DSS-3.6", "SOC2-CC6.1"],
        "fix": "Use secrets (Python), crypto.randomBytes (Node.js), crypto/rand (Go)"
    },
    {
        "id": "CS007", "name": "RSA key too small", "severity": "HIGH",
        "pattern": r"(?i)(GenerateKey\(.{0,20}1024|key_?size\s*=\s*1024)",
        "compliance": ["PCI-DSS-3.6", "FIPS-140-2", "SOC2-CC6.1"],
        "fix": "Use RSA >= 2048 bits, prefer 4096"
    },
    {
        "id": "CS008", "name": "DES or 3DES usage", "severity": "HIGH",
        "pattern": r"(?i)(DES\.new|DESede|TripleDES|DES/CBC|crypto/des|DES_ENCRYPT)",
        "compliance": ["PCI-DSS-3.4", "FIPS-140-2"],
        "fix": "Migrate to AES-256-GCM"
    },
    {
        "id": "CS009", "name": "Hardcoded IV or nonce", "severity": "HIGH",
        "pattern": r"(?i)\b(?:iv|nonce)\s*=\s*(?:b?[\"'][^\"']{2,}[\"']|\[[\d,\s]+\])",
        "compliance": ["PCI-DSS-3.4", "SOC2-CC6.1"],
        "fix": "Generate random IV/nonce per encryption operation using CSPRNG"
    },
    {
        "id": "CS010", "name": "JWT none algorithm", "severity": "CRITICAL",
        "pattern": r"""(?i)(algorithm\s*=\s*[\"']none[\"']|\"alg\"\s*:\s*\"none\"|algorithms.*[\"']none[\"'])""",
        "compliance": ["PCI-DSS-3.4", "SOC2-CC6.1"],
        "fix": "Use RS256 or ES256. Never allow 'none' algorithm."
    },
]
