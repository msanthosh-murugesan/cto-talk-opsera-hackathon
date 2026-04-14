"""
Tests for Code Guardian core pipeline.
Run with: python -m pytest tests/ -v
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from agents.security_agent import run_security_scan
from agents.architecture_agent import run_architecture_review
from parsers.normalizer import normalize_and_score, _normalize_severity
from utils.score_calculator import calculate_scores


def test_mock_security_agent():
    """Security agent mock returns valid structured data."""
    result = asyncio.run(run_security_scan("/tmp", mock=True))
    assert result["agent"] == "opsera-security"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0
    # Every finding must have required fields
    for f in result["findings"]:
        assert "id" in f
        assert "severity" in f
        assert "title" in f
        assert "description" in f


def test_mock_architecture_agent():
    """Architecture agent mock returns valid structured data."""
    result = asyncio.run(run_architecture_review("/tmp", mock=True))
    assert result["agent"] == "opsera-architecture"
    assert result["status"] == "completed"
    assert len(result["findings"]) > 0
    for f in result["findings"]:
        assert "id" in f
        assert "severity" in f
        assert "title" in f
        assert "suggestion" in f


def test_normalizer_merges_both_agents():
    """Normalizer combines findings from both agents into a unified list."""
    sec = asyncio.run(run_security_scan("/tmp", mock=True))
    arch = asyncio.run(run_architecture_review("/tmp", mock=True))
    findings = normalize_and_score(sec, arch)

    categories = set(f["category"] for f in findings)
    assert "security" in categories
    assert "architecture" in categories

    # All findings must have normalized fields
    for f in findings:
        assert f["severity"] in ("critical", "high", "medium", "low")
        assert f["category"] in ("security", "architecture")
        assert "risk_weight" in f
        assert "fix_suggestion" in f


def test_normalizer_sorts_by_severity():
    """Findings are sorted: critical first, then high, medium, low."""
    sec = asyncio.run(run_security_scan("/tmp", mock=True))
    arch = asyncio.run(run_architecture_review("/tmp", mock=True))
    findings = normalize_and_score(sec, arch)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(len(findings) - 1):
        assert severity_order[findings[i]["severity"]] <= severity_order[findings[i + 1]["severity"]]


def test_severity_normalization():
    """Various severity strings map to our four-level system."""
    assert _normalize_severity("critical") == "critical"
    assert _normalize_severity("error") == "critical"
    assert _normalize_severity("high") == "high"
    assert _normalize_severity("warning") == "high"
    assert _normalize_severity("medium") == "medium"
    assert _normalize_severity("moderate") == "medium"
    assert _normalize_severity("low") == "low"
    assert _normalize_severity("info") == "low"
    assert _normalize_severity("CRITICAL") == "critical"  # Case insensitive


def test_score_calculation():
    """Scores are 0-100 and combined score is weighted correctly."""
    sec = asyncio.run(run_security_scan("/tmp", mock=True))
    arch = asyncio.run(run_architecture_review("/tmp", mock=True))
    findings = normalize_and_score(sec, arch)
    scores = calculate_scores(findings)

    assert 0 <= scores.security_score <= 100
    assert 0 <= scores.architecture_score <= 100
    assert 0 <= scores.combined_score <= 100
    # Combined should be between the two individual scores (weighted)
    expected = int(scores.security_score * 0.60 + scores.architecture_score * 0.40)
    assert scores.combined_score == expected


def test_empty_findings_give_perfect_scores():
    """No findings = perfect 100 scores."""
    empty_sec = {"agent": "opsera-security", "findings": []}
    empty_arch = {"agent": "opsera-architecture", "findings": []}
    findings = normalize_and_score(empty_sec, empty_arch)
    scores = calculate_scores(findings)

    assert scores.security_score == 100
    assert scores.architecture_score == 100
    assert scores.combined_score == 100


def test_concurrent_agent_execution():
    """Both agents can run concurrently without issues."""
    async def run_both():
        return await asyncio.gather(
            run_security_scan("/tmp", mock=True),
            run_architecture_review("/tmp", mock=True),
        )

    sec, arch = asyncio.run(run_both())
    assert sec["agent"] == "opsera-security"
    assert arch["agent"] == "opsera-architecture"


if __name__ == "__main__":
    # Quick self-test without pytest
    tests = [
        test_mock_security_agent,
        test_mock_architecture_agent,
        test_normalizer_merges_both_agents,
        test_normalizer_sorts_by_severity,
        test_severity_normalization,
        test_score_calculation,
        test_empty_findings_give_perfect_scores,
        test_concurrent_agent_execution,
    ]
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n  {len(tests)} tests completed")
