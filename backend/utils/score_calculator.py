"""
Score Calculator
=================
Computes overall health scores (0-100) from the normalized findings.

Scoring formula:
  - Start at 100 (perfect score)
  - Deduct points based on finding severity and count
  - Critical findings have a large penalty; low findings have minimal impact
  - Floor at 0 (scores can't go negative)

The combined score is weighted: 60% security + 40% architecture
(security gets higher weight because vulnerabilities have immediate risk).
"""

from models.report import Scores

# Points deducted per finding at each severity level
DEDUCTIONS = {
    "critical": 15,  # Each critical finding costs 15 points
    "high": 8,       # Each high finding costs 8 points
    "medium": 4,     # Each medium finding costs 4 points
    "low": 1,        # Each low finding costs 1 point
}

# Combined score weighting
SECURITY_WEIGHT = 0.60
ARCHITECTURE_WEIGHT = 0.40


def calculate_scores(findings: list[dict]) -> Scores:
    """
    Calculate aggregate health scores from the list of normalized findings.

    Returns a Scores object with:
      - security_score: 0-100 based on security findings only
      - architecture_score: 0-100 based on architecture findings only
      - combined_score: weighted blend of both
    """
    security_findings = [f for f in findings if f["category"] == "security"]
    architecture_findings = [f for f in findings if f["category"] == "architecture"]

    security_score = _compute_category_score(security_findings)
    architecture_score = _compute_category_score(architecture_findings)

    combined_score = int(
        security_score * SECURITY_WEIGHT + architecture_score * ARCHITECTURE_WEIGHT
    )

    return Scores(
        security_score=security_score,
        architecture_score=architecture_score,
        combined_score=combined_score,
    )


def _compute_category_score(findings: list[dict]) -> int:
    """
    Compute a 0-100 score for a category by deducting points from 100.
    Confidence-weighted: a finding with 0.5 confidence deducts half the points.
    """
    total_deduction = 0.0

    for finding in findings:
        severity = finding.get("severity", "medium")
        confidence = finding.get("confidence", 1.0)
        base_deduction = DEDUCTIONS.get(severity, 4)

        # Weight deduction by the agent's confidence in this finding
        total_deduction += base_deduction * confidence

    score = max(0, int(100 - total_deduction))
    return score
