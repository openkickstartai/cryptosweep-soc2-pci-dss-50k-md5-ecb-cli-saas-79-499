#!/usr/bin/env python3
"""CryptoSweep — Cryptographic misuse & compliance scanner."""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from rules import RULES

SCAN_EXTS = {".py", ".js", ".ts", ".go", ".java", ".cs", ".rb", ".php", ".rs", ".kt"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "__pycache__", ".venv", "dist", ".tox"}


def scan_file(filepath):
    findings = []
    try:
        lines = Path(filepath).read_text(errors="ignore").splitlines()
    except OSError:
        return findings
    for lineno, line in enumerate(lines, 1):
        for rule in RULES:
            if re.search(rule["pattern"], line):
                findings.append({
                    "rule_id": rule["id"], "rule_name": rule["name"],
                    "severity": rule["severity"], "file": str(filepath),
                    "line": lineno, "code": line.strip()[:120],
                    "compliance": rule["compliance"], "fix": rule["fix"],
                })
    return findings


def scan_path(target):
    target = Path(target)
    if target.is_file():
        return scan_file(target)
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fp = Path(root) / fname
            if fp.suffix in SCAN_EXTS:
                findings.extend(scan_file(fp))
    return findings


def to_sarif(findings):
    results = [{
        "ruleId": f["rule_id"],
        "message": {"text": f"{f['rule_name']}: {f['fix']}"},
        "level": "error" if f["severity"] in ("CRITICAL", "HIGH") else "warning",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f["file"]},
            "region": {"startLine": f["line"]}}}]
    } for f in findings]
    driver = {"name": "CryptoSweep", "version": "1.0.0",
              "rules": [{"id": r["id"], "shortDescription": {"text": r["name"]}} for r in RULES]}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}


def print_report(findings, fmt, framework):
    if fmt == "json":
        print(json.dumps(findings, indent=2))
        return
    if fmt == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
        return
    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
    for f in findings:
        c = colors.get(f["severity"], "")
        print(f"{c}[{f['severity']}]\033[0m {f['rule_id']}: {f['rule_name']}")
        print(f"  \U0001f4cd {f['file']}:{f['line']}  |  {f['code']}")
        print(f"  \U0001f527 {f['fix']}")
        print(f"  \U0001f4cb {', '.join(f['compliance'])}\n")
    if framework:
        violations = {}
        for f in findings:
            for tag in f["compliance"]:
                if tag.startswith(framework):
                    violations[tag] = violations.get(tag, 0) + 1
        if violations:
            print(f"\n{'=' * 50}\n\U0001f4ca {framework} Compliance Summary\n{'=' * 50}")
            for ctrl, count in sorted(violations.items()):
                print(f"  \u274c {ctrl}: {count} violation(s)")
    crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
    highs = sum(1 for f in findings if f["severity"] == "HIGH")
    print(f"\n\U0001f50d Total: {len(findings)} findings ({crits} critical, {highs} high)")


def main():
    p = argparse.ArgumentParser(prog="cryptosweep", description="Crypto misuse & compliance scanner")
    p.add_argument("target", help="File or directory to scan")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-c", "--compliance", choices=["PCI-DSS", "SOC2", "HIPAA", "FIPS-140-2"])
    p.add_argument("--fail-on", choices=["critical", "high", "medium"],
                   help="Exit code 1 if findings at or above this severity")
    args = p.parse_args()
    findings = scan_path(args.target)
    print_report(findings, args.format, args.compliance)
    if args.fail_on and findings:
        levels = {"critical": {"CRITICAL"}, "high": {"CRITICAL", "HIGH"},
                  "medium": {"CRITICAL", "HIGH", "MEDIUM"}}
        if any(f["severity"] in levels[args.fail_on] for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
