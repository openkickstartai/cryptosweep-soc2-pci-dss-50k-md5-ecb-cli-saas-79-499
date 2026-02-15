"""Tests for CryptoSweep scanner — 9 test cases covering core detection logic."""
import json
import os
import tempfile
from pathlib import Path
from cryptosweep import scan_file, scan_path, to_sarif


def _tmp(content, suffix=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_detects_md5():
    p = _tmp("import hashlib\nh = hashlib.md5(b'data')\n")
    findings = scan_file(p)
    os.unlink(p)
    assert len(findings) >= 1
    assert findings[0]["rule_id"] == "CS001"
    assert findings[0]["severity"] == "HIGH"
    assert "PCI-DSS-3.4" in findings[0]["compliance"]


def test_detects_hardcoded_secret():
    p = _tmp('password = "super_secret_value_123"\n')
    findings = scan_file(p)
    os.unlink(p)
    assert any(f["rule_id"] == "CS004" for f in findings)
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_detects_tls_disabled():
    p = _tmp("resp = requests.get(url, verify=False)\n")
    findings = scan_file(p)
    os.unlink(p)
    assert any(f["rule_id"] == "CS005" for f in findings)
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_detects_ecb_mode():
    p = _tmp("cipher = AES.new(key, AES.MODE_ECB)\n")
    findings = scan_file(p)
    os.unlink(p)
    assert any(f["rule_id"] == "CS003" for f in findings)
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_clean_file_no_findings():
    p = _tmp("import os\nresult = os.path.join('a', 'b')\nprint(result)\n")
    findings = scan_file(p)
    os.unlink(p)
    assert len(findings) == 0


def test_scan_directory():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "bad.py").write_text('h = hashlib.md5(b"x")\n')
        Path(d, "ok.py").write_text('print("safe code")\n')
        Path(d, "readme.txt").write_text('hashlib.md5 mentioned in docs\n')
        findings = scan_path(d)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CS001"


def test_sarif_output_format():
    p = _tmp("h = hashlib.md5(b'x')\n")
    findings = scan_file(p)
    os.unlink(p)
    sarif = to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "CryptoSweep"
    assert len(sarif["runs"][0]["results"]) >= 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CS001"


def test_detects_weak_random():
    p = _tmp("token = random.random()\n")
    findings = scan_file(p)
    os.unlink(p)
    assert any(f["rule_id"] == "CS006" for f in findings)
    assert any(f["severity"] == "MEDIUM" for f in findings)


def test_detects_jwt_none_algorithm():
    p = _tmp('tok = jwt.encode(payload, key, algorithm="none")\n')
    findings = scan_file(p)
    os.unlink(p)
    assert any(f["rule_id"] == "CS010" for f in findings)
    assert any(f["severity"] == "CRITICAL" for f in findings)


if __name__ == "__main__":
    passed = 0
    for name, func in sorted(globals().items()):
        if name.startswith("test_"):
            func()
            print(f"  \u2705 {name}")
            passed += 1
    print(f"\n\U0001f389 {passed} tests passed!")
