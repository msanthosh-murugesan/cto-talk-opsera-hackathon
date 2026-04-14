"""
Output Normalizer & Risk Scorer
=================================
Transforms raw outputs from both agents into a unified finding
format with consistent severity ratings and risk scores.

This is the critical integration layer — it takes two different agent
output schemas and produces a single, homogeneous list of findings that
the dashboard can render without knowing which agent produced each one.
"""

import uuid
from typing import Any


# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}

# Map raw agent severity strings to our normalized levels
SEVERITY_ALIASES = {
    "critical": "critical",
    "error": "critical",
    "high": "high",
    "warning": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}


def normalize_and_score(
    security_raw: dict[str, Any],
    architecture_raw: dict[str, Any],
) -> list[dict]:
    """
    Take raw outputs from both agents and produce a unified list of findings.

    Each finding gets:
      - A unique ID
      - Normalized severity (critical/high/medium/low)
      - Category tag (security/architecture)
      - Risk weight for score calculation
      - All original details preserved

    Args:
        security_raw: Raw output from the Security Agent
        architecture_raw: Raw output from the Architecture Agent

    Returns:
        Sorted list of normalized findings (critical first, then high, etc.)
    """
    findings = []

    # ── Normalize Security Findings ────────────────────────────────────────────
    for item in security_raw.get("findings", []):
        severity = _normalize_severity(item.get("severity", "medium"))
        findings.append({
            "id": item.get("id", f"SEC-{uuid.uuid4().hex[:6]}"),
            "category": "security",
            "severity": severity,
            "risk_weight": SEVERITY_WEIGHTS.get(severity, 4),
            "title": item.get("title", "Untitled security finding"),
            "description": item.get("description", ""),
            "file_path": item.get("file", None),
            "line_number": item.get("line", None),
            "rule_id": _build_rule_id(item),
            "fix_suggestion": item.get("fix", ""),
            "tags": _build_security_tags(item),
            "confidence": item.get("confidence", 1.0),
            "code_snippet": item.get("code_snippet", ""),
            "source_agent": "opsera-security",
        })

    # ── Normalize Architecture Findings ────────────────────────────────────────
    for item in architecture_raw.get("findings", []):
        severity = _normalize_severity(item.get("severity", "medium"))
        findings.append({
            "id": item.get("id", f"ARCH-{uuid.uuid4().hex[:6]}"),
            "category": "architecture",
            "severity": severity,
            "risk_weight": SEVERITY_WEIGHTS.get(severity, 4),
            "title": item.get("title", "Untitled architecture finding"),
            "description": item.get("description", ""),
            "file_path": item.get("file", None),
            "line_number": item.get("line", None),
            "rule_id": item.get("pattern", ""),
            "fix_suggestion": item.get("suggestion", ""),
            "tags": _build_architecture_tags(item),
            "confidence": item.get("confidence", 1.0),
            "metrics": item.get("metrics", {}),
            "source_agent": "opsera-architecture",
        })

    # Sort: critical → high → medium → low, then by confidence (desc)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), -f["confidence"]))

    return findings


def _normalize_severity(raw_severity: str) -> str:
    """Map any raw severity string to our four-level system."""
    return SEVERITY_ALIASES.get(raw_severity.lower().strip(), "medium")


def _build_rule_id(item: dict) -> str:
    """Construct a meaningful rule identifier from available data."""
    parts = []
    if item.get("owasp"):
        parts.append(item["owasp"])
    if item.get("cwe"):
        parts.append(item["cwe"])
    if item.get("rule"):
        parts.append(item["rule"])
    return " | ".join(parts) if parts else "custom-rule"


def _build_security_tags(item: dict) -> list[str]:
    """Generate tags for a security finding based on its metadata."""
    tags = []
    if item.get("owasp"):
        tags.append(item["owasp"])
    if item.get("cwe"):
        tags.append(item["cwe"])
    if item.get("type"):
        tags.append(item["type"])
    if item.get("rule"):
        tags.append(item["rule"])
    return tags


def _build_architecture_tags(item: dict) -> list[str]:
    """Generate tags for an architecture finding."""
    tags = []
    if item.get("type"):
        tags.append(item["type"])
    if item.get("pattern"):
        tags.append(item["pattern"])
    return tags
