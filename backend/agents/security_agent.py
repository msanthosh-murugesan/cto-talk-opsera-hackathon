"""
Security Agent Integration — Code Guardian powered by Santhosh
================================================================
By Santhosh Murugesan, Full Creative Pvt.Ltd.

This module handles communication with the Security Agent.

In REAL mode: Invokes the agent via its CLI/API interface. The agent
performs OWASP Top 10 scanning, dependency vulnerability checks, secrets
detection, SQL injection pattern matching, and XSS vulnerability analysis.

In MOCK mode: Returns realistic sample data so the dashboard can be developed
and tested without requiring the actual agent to be installed.
"""

import asyncio
import hashlib
import json
import os
import random
import re
import subprocess
from pathlib import Path
from typing import Any


async def run_security_scan(repo_path: str, mock: bool = False) -> dict[str, Any]:
    """
    Execute the Security Agent against the given codebase.

    Args:
        repo_path: Absolute path to the project directory to scan
        mock: If True, return realistic sample data instead of calling the agent

    Returns:
        Raw agent output as a dictionary containing vulnerability findings
    """
    if mock:
        return _get_mock_security_results(repo_path)

    return await _invoke_opsera_security_agent(repo_path)


async def _invoke_opsera_security_agent(repo_path: str) -> dict[str, Any]:
    """
    Invoke the real Security Agent.

    The agent is triggered via the IDE extension's CLI interface.
    We pass the project path and request a JSON-formatted security scan.

    Integration approach:
      - Primary: IDE extension CLI (`opsera-agent security scan`)
      - Fallback: API endpoint if CLI isn't available
      - The agent analyzes: source files, dependency manifests (package.json,
        requirements.txt, pom.xml), config files, and environment files
    """
    try:
        # Attempt CLI invocation (IDE extension must be installed)
        result = await asyncio.to_thread(
            subprocess.run,
            [
                "opsera-agent", "security", "scan",
                "--path", repo_path,
                "--format", "json",
                "--severity", "all",
                "--include-fix-suggestions",
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2-minute timeout for large repos
        )

        if result.returncode == 0:
            return json.loads(result.stdout)

        # If CLI fails, try the API approach
        return await _invoke_via_opsera_api(repo_path, "security")

    except FileNotFoundError:
        # CLI not installed — fall back to API
        print("[SecurityAgent] CLI not found, attempting API invocation...")
        return await _invoke_via_opsera_api(repo_path, "security")

    except Exception as e:
        print(f"[SecurityAgent] Error during scan: {e}")
        # Return a structured error so the pipeline can continue gracefully
        return {
            "agent": "opsera-security",
            "status": "error",
            "error": str(e),
            "findings": [],
        }


async def _invoke_via_opsera_api(repo_path: str, scan_type: str) -> dict[str, Any]:
    """
    Fallback: invoke agent via its REST API.
    Requires OPSERA_API_KEY and OPSERA_API_URL environment variables.
    """
    import aiohttp

    api_url = os.getenv("OPSERA_API_URL", "https://api.opsera.io/v1")
    api_key = os.getenv("OPSERA_API_KEY", "")

    if not api_key:
        print("[SecurityAgent] No API key configured. Returning empty results.")
        return {"agent": "opsera-security", "status": "no-api-key", "findings": []}

    # Collect file contents to send to the API
    files_payload = _collect_scannable_files(repo_path)

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{api_url}/agents/security/scan",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"files": files_payload, "scan_type": scan_type},
            timeout=aiohttp.ClientTimeout(total=120),
        ) as resp:
            return await resp.json()


def _collect_scannable_files(repo_path: str, max_files: int = 100) -> list[dict]:
    """
    Gather source files from the repo for API-based scanning.
    Limits file count and size to stay within API payload limits.
    """
    scannable_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".c", ".cpp", ".h", ".rs", ".swift", ".kt",
        ".yaml", ".yml", ".json", ".xml", ".toml", ".env", ".cfg",
        ".sql", ".html", ".css", ".sh", ".bash", ".dockerfile",
    }
    files = []
    repo = Path(repo_path)

    for fpath in repo.rglob("*"):
        if len(files) >= max_files:
            break
        if fpath.is_file() and fpath.suffix.lower() in scannable_extensions:
            # Skip node_modules, venvs, and other dependency dirs
            if any(part in fpath.parts for part in ["node_modules", ".venv", "venv", "__pycache__", ".git"]):
                continue
            try:
                content = fpath.read_text(errors="ignore")[:50_000]  # Cap at 50KB per file
                files.append({
                    "path": str(fpath.relative_to(repo)),
                    "content": content,
                })
            except Exception:
                continue

    return files


# ── Mock Data ──────────────────────────────────────────────────────────────────

# Pattern-based rules that scan real file contents
_SECURITY_RULES = [
    {
        "rule": "sql-injection", "type": "vulnerability",
        "owasp": "A03:2021-Injection", "cwe": "CWE-89", "severity": "critical",
        "title": "Potential SQL Injection",
        "description": "String formatting or concatenation is used to build SQL queries. An attacker could manipulate input to access or modify unauthorized data.",
        "fix": "Use parameterized queries instead of string formatting for SQL statements.",
        "pattern": r"""(?:execute|query|cursor)\s*\(.*(?:f['\"]|\.format|%s|\+\s*\w)""",
        "extensions": {".py", ".js", ".ts", ".java", ".rb", ".php"},
    },
    {
        "rule": "hardcoded-secret", "type": "secret",
        "owasp": "A02:2021-Cryptographic Failures", "cwe": "CWE-798", "severity": "critical",
        "title": "Potential hardcoded secret or API key",
        "description": "A string that looks like a secret or API key is hardcoded in source code. If committed to a public repo, it could be exposed.",
        "fix": "Move secrets to environment variables or a secrets manager.",
        "pattern": r"""(?:api[_-]?key|secret|password|token|auth)\s*=\s*['\"][A-Za-z0-9+/=_\-]{12,}['\"]""",
        "extensions": {".py", ".js", ".ts", ".java", ".rb", ".php", ".yaml", ".yml", ".json", ".env"},
    },
    {
        "rule": "xss-reflected", "type": "vulnerability",
        "owasp": "A07:2021-XSS", "cwe": "CWE-79", "severity": "high",
        "title": "Potential Cross-Site Scripting (XSS)",
        "description": "User input may be rendered in HTML without proper escaping, allowing script injection.",
        "fix": "Sanitize and escape all user-provided data before rendering in HTML.",
        "pattern": r"""(?:innerHTML|document\.write|res\.send\(.*\$\{|\.html\(.*\+)""",
        "extensions": {".js", ".ts", ".jsx", ".tsx", ".html", ".php"},
    },
    {
        "rule": "cors-wildcard", "type": "configuration",
        "owasp": "A05:2021-Security Misconfiguration", "cwe": "CWE-942", "severity": "low",
        "title": "CORS allows all origins",
        "description": "The CORS configuration uses a wildcard, allowing any website to make requests to this API.",
        "fix": "Restrict CORS to specific allowed origins in production.",
        "pattern": r"""allow_origins\s*=\s*\[\s*['\"\*]|Access-Control-Allow-Origin.*\*""",
        "extensions": {".py", ".js", ".ts", ".java", ".yaml", ".yml"},
    },
    {
        "rule": "weak-crypto", "type": "vulnerability",
        "owasp": "A02:2021-Cryptographic Failures", "cwe": "CWE-327", "severity": "medium",
        "title": "Weak cryptographic algorithm detected",
        "description": "Use of a weak or broken hashing/encryption algorithm (MD5, SHA1, DES) that is unsuitable for security purposes.",
        "fix": "Use strong algorithms: bcrypt/argon2 for passwords, SHA-256+ for hashing, AES-256 for encryption.",
        "pattern": r"""(?:md5|sha1|DES|RC4)\s*\(|hashlib\.(?:md5|sha1)\(""",
        "extensions": {".py", ".js", ".ts", ".java", ".go", ".rb"},
    },
    {
        "rule": "insecure-deserialization", "type": "vulnerability",
        "owasp": "A08:2021-Integrity Failures", "cwe": "CWE-502", "severity": "medium",
        "title": "Unsafe deserialization of untrusted data",
        "description": "Using pickle, eval, or similar functions on potentially untrusted data can lead to arbitrary code execution.",
        "fix": "Use safe serialization formats like JSON. If pickle is needed, verify data integrity with HMAC.",
        "pattern": r"""pickle\.loads|yaml\.load\((?!.*Loader)|eval\(|exec\(|unserialize\(""",
        "extensions": {".py", ".js", ".ts", ".java", ".rb", ".php"},
    },
    {
        "rule": "path-traversal", "type": "vulnerability",
        "owasp": "A01:2021-Broken Access Control", "cwe": "CWE-22", "severity": "high",
        "title": "Potential path traversal vulnerability",
        "description": "User-controlled input is used to construct file paths without validation, allowing directory traversal.",
        "fix": "Validate resolved paths stay within the intended directory. Reject paths containing '..'.",
        "pattern": r"""(?:path\.join|open|read_file|send_file)\s*\(.*(?:req\.|request\.|params|user|input)""",
        "extensions": {".py", ".js", ".ts", ".java", ".go", ".rb"},
    },
    {
        "rule": "ssrf", "type": "vulnerability",
        "owasp": "A10:2021-SSRF", "cwe": "CWE-918", "severity": "high",
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "description": "A user-provided URL or host is used in an HTTP request without validation, enabling internal network scanning.",
        "fix": "Validate URLs against an allowlist and block internal/private IP ranges before making requests.",
        "pattern": r"""(?:requests\.get|fetch|urllib\.request|http\.get|aiohttp.*get)\s*\(.*(?:user|param|input|req\.|request\.)""",
        "extensions": {".py", ".js", ".ts", ".java", ".go", ".rb"},
    },
    {
        "rule": "missing-auth", "type": "vulnerability",
        "owasp": "A01:2021-Broken Access Control", "cwe": "CWE-862", "severity": "medium",
        "title": "Endpoint may lack authentication",
        "description": "An admin or sensitive endpoint does not appear to have authentication or authorization checks.",
        "fix": "Add authentication middleware to all sensitive endpoints.",
        "pattern": r"""(?:@app\.(?:get|post|put|delete|patch)\s*\(\s*['\"]\/admin|@router\..*admin)""",
        "extensions": {".py", ".js", ".ts"},
    },
    {
        "rule": "vulnerable-dependency", "type": "dependency",
        "owasp": "A06:2021-Vulnerable Components", "cwe": "CWE-1035", "severity": "high",
        "title": "Potentially outdated dependency",
        "description": "A dependency is pinned to a version that may have known vulnerabilities. Regular dependency updates are critical.",
        "fix": "Update dependencies to their latest stable versions and enable automated dependency scanning.",
        "pattern": r"""(?:\"lodash\":\s*\"\^?[34]\.|\"express\":\s*\"\^?[1-3]\.|\"django\":\s*\"[12]\.|requests==2\.(?:[0-1]\d|2[0-5])\.)""",
        "extensions": {".json", ".txt", ".toml", ".cfg"},
    },
]

# Files/dirs to skip during scan
_SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", ".tox", "dist", "build", ".mypy_cache"}
_SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
                         ".php", ".html", ".yaml", ".yml", ".json", ".toml", ".env",
                         ".cfg", ".txt", ".xml", ".sql", ".sh"}


def _get_mock_security_results(repo_path: str) -> dict[str, Any]:
    """
    Scan actual repo files using pattern-matching rules to generate
    realistic security findings. Each scan produces different results
    based on the actual code in the target repository.
    """
    # Seed RNG with current time so each run is different
    rng = random.Random()
    repo = Path(repo_path)
    findings = []
    scanned_files = 0
    finding_id = 1

    for fpath in repo.rglob("*"):
        if not fpath.is_file():
            continue
        if any(skip in fpath.parts for skip in _SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in _SCANNABLE_EXTENSIONS:
            continue

        scanned_files += 1
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        lines = content.splitlines()
        rel_path = str(fpath.relative_to(repo))

        for rule in _SECURITY_RULES:
            if fpath.suffix.lower() not in rule["extensions"]:
                continue
            for line_num, line_text in enumerate(lines, start=1):
                if re.search(rule["pattern"], line_text, re.IGNORECASE):
                    # Add some randomized confidence to simulate agent variability
                    confidence = round(rng.uniform(0.75, 0.99), 2)
                    findings.append({
                        "id": f"SEC-{finding_id:03d}",
                        "type": rule["type"],
                        "rule": rule["rule"],
                        "owasp": rule["owasp"],
                        "cwe": rule["cwe"],
                        "severity": rule["severity"],
                        "title": f"{rule['title']} in {rel_path}",
                        "description": rule["description"],
                        "file": rel_path,
                        "line": line_num,
                        "code_snippet": line_text.strip()[:200],
                        "fix": rule["fix"],
                        "confidence": confidence,
                    })
                    finding_id += 1

    # If no real findings from scanning, generate a few baseline ones
    if not findings:
        findings = _get_baseline_security_findings(rng)

    return {
        "agent": "code-guardian-security",
        "scan_id": f"sec-{hashlib.sha256(repo_path.encode()).hexdigest()[:8]}-{rng.randint(1000, 9999)}",
        "status": "completed",
        "scanned_files": scanned_files,
        "scan_duration_ms": rng.randint(1500, 6000),
        "findings": findings,
    }


def _get_baseline_security_findings(rng: random.Random) -> list[dict]:
    """Generate a small set of baseline findings when no patterns match."""
    baseline = [
        {
            "id": "SEC-001", "type": "configuration", "rule": "cors-wildcard",
            "owasp": "A05:2021-Security Misconfiguration", "cwe": "CWE-942",
            "severity": "low",
            "title": "Review CORS configuration",
            "description": "Ensure CORS policies are appropriately configured for production deployment.",
            "file": "config", "line": 1,
            "code_snippet": "", "fix": "Restrict CORS to known frontend origins.",
            "confidence": round(rng.uniform(0.70, 0.90), 2),
        },
        {
            "id": "SEC-002", "type": "configuration", "rule": "security-headers",
            "owasp": "A05:2021-Security Misconfiguration", "cwe": "CWE-693",
            "severity": "medium",
            "title": "Security headers not configured",
            "description": "HTTP security headers (CSP, X-Frame-Options, HSTS) should be set.",
            "file": "config", "line": 1,
            "code_snippet": "", "fix": "Add security headers middleware.",
            "confidence": round(rng.uniform(0.70, 0.85), 2),
        },
    ]
    return rng.sample(baseline, k=rng.randint(1, len(baseline)))
