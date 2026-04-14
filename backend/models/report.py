"""
Data Models — Pydantic schemas for type-safe request/response handling.
These models define the unified report format that normalizes output from
both Security and Architecture agents into a single structure.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single issue found by either agent."""
    id: str = Field(..., description="Unique finding identifier")
    category: str = Field(..., description="'security' or 'architecture'")
    severity: str = Field(..., description="critical / high / medium / low")
    title: str = Field(..., description="Short description of the issue")
    description: str = Field(..., description="Detailed explanation")
    file_path: Optional[str] = Field(None, description="Affected file")
    line_number: Optional[int] = Field(None, description="Line number if applicable")
    rule_id: Optional[str] = Field(None, description="OWASP/CWE/custom rule ID")
    fix_suggestion: str = Field("", description="Actionable remediation advice")
    tags: list[str] = Field(default_factory=list, description="Labels like 'OWASP-A01', 'anti-pattern'")
    confidence: float = Field(1.0, description="Agent confidence score 0.0-1.0")


class Scores(BaseModel):
    """Aggregate scores for the scanned codebase."""
    security_score: int = Field(..., ge=0, le=100, description="Overall security health 0-100")
    architecture_score: int = Field(..., ge=0, le=100, description="Overall architecture health 0-100")
    combined_score: int = Field(..., ge=0, le=100, description="Weighted combined score")


class ScanRequest(BaseModel):
    """Incoming scan request."""
    target: str
    mock_mode: bool = False


class ScanStatus(BaseModel):
    """Status of a running or completed scan job."""
    job_id: str
    target: str
    status: str = "queued"  # queued → cloning → scanning → analyzing → finalizing → completed | failed
    progress: int = 0       # 0-100 percentage
    created_at: str = ""
    report_url: Optional[str] = None
    error: Optional[str] = None


class ScanReport(BaseModel):
    """The complete scan report combining both agents' outputs."""
    job_id: str
    target: str
    created_at: str
    scores: Scores
    findings: list[dict]       # List of Finding dicts
    summary: dict              # Aggregated counts by severity/category
    raw_security: Any = None   # Raw Security Agent output (for debugging)
    raw_architecture: Any = None  # Raw Architecture Agent output
