"""
Code Guardian — Backend Server
================================
By Santhosh Murugesan, Full Creative Pvt.Ltd.

FastAPI server that orchestrates Security & Architecture agents,
normalizes their output into a unified risk-scored report, and serves
results to the web dashboard.

Why FastAPI over Express?
- Native async/await for concurrent agent calls (both agents run in parallel)
- Built-in OpenAPI docs at /docs — judges can explore the API live
- Pydantic models give us type-safe request/response validation for free
- Python ecosystem has stronger text-parsing and data-processing libraries
"""

import os
import json
import asyncio
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from agents.security_agent import run_security_scan
from agents.architecture_agent import run_architecture_review
from parsers.normalizer import normalize_and_score
from models.report import ScanReport, ScanRequest, ScanStatus
from utils.repo_loader import clone_or_locate_repo, cleanup_repo
from utils.score_calculator import calculate_scores

# ── App Setup ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Code Guardian powered by Santhosh",
    description="Unified Security & Architecture Scanner — By Santhosh Murugesan, Full Creative Pvt.Ltd.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Fine for hackathon demo; lock down in prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for scan jobs (good enough for a 48-hr hackathon)
scan_jobs: dict[str, ScanStatus] = {}

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# ── Models ─────────────────────────────────────────────────────────────────────

class ScanRequestBody(BaseModel):
    """POST body for /scan endpoint."""
    target: str = Field(..., description="GitHub URL or local path to scan")
    mock_mode: bool = Field(False, description="Use mock agents for testing")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    """Health check + API info."""
    return {
        "service": "Code Guardian powered by Santhosh",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.post("/scan", response_model=ScanStatus)
async def start_scan(body: ScanRequestBody, background_tasks: BackgroundTasks):
    """
    Kick off a new scan. Returns a job ID immediately — the actual scanning
    runs in the background so the dashboard can poll for progress.
    """
    # Generate a deterministic job ID from the target + timestamp
    job_id = hashlib.sha256(
        f"{body.target}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]

    status = ScanStatus(
        job_id=job_id,
        target=body.target,
        status="queued",
        progress=0,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    scan_jobs[job_id] = status

    # Run the heavy lifting in the background
    background_tasks.add_task(execute_scan, job_id, body.target, body.mock_mode)

    return status


@app.get("/scan/{job_id}", response_model=ScanStatus)
async def get_scan_status(job_id: str):
    """Poll this endpoint to track scan progress."""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found")
    return scan_jobs[job_id]


@app.get("/report/{job_id}")
async def get_report(job_id: str):
    """Fetch the completed scan report."""
    report_path = REPORTS_DIR / f"{job_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not ready or not found")
    return json.loads(report_path.read_text())


@app.get("/reports")
async def list_reports():
    """List all completed scan reports (for dashboard history view)."""
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
            reports.append({
                "job_id": f.stem,
                "target": data.get("target", "unknown"),
                "created_at": data.get("created_at", ""),
                "security_score": data.get("scores", {}).get("security_score", 0),
                "architecture_score": data.get("scores", {}).get("architecture_score", 0),
            })
        except Exception:
            continue
    return reports


@app.get("/dashboard")
async def serve_dashboard():
    """Serve the frontend dashboard from the backend."""
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(index_path)


# ── Background Scan Pipeline ──────────────────────────────────────────────────

async def execute_scan(job_id: str, target: str, mock_mode: bool):
    """
    The main scan pipeline. Runs both agents concurrently, normalizes
    their output, calculates risk scores, and saves the final report.

    Pipeline: clone → [security scan ‖ architecture review] → normalize → score → save
    """
    status = scan_jobs[job_id]

    try:
        # Step 1: Resolve the target (clone if GitHub URL, validate if local path)
        status.status = "cloning"
        status.progress = 10
        repo_path = await clone_or_locate_repo(target)

        # Step 2: Run BOTH agents concurrently — this is the key orchestration step
        status.status = "scanning"
        status.progress = 30

        security_result, architecture_result = await asyncio.gather(
            run_security_scan(repo_path, mock=mock_mode),
            run_architecture_review(repo_path, mock=mock_mode),
        )

        # Step 3: Normalize raw agent outputs into our unified schema
        status.status = "analyzing"
        status.progress = 70

        findings = normalize_and_score(security_result, architecture_result)

        # Step 4: Calculate aggregate scores
        status.progress = 85
        scores = calculate_scores(findings)

        # Step 5: Build and persist the final report
        status.status = "finalizing"
        status.progress = 95

        report = ScanReport(
            job_id=job_id,
            target=target,
            created_at=datetime.now(timezone.utc).isoformat(),
            scores=scores,
            findings=findings,
            summary={
                "total_issues": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "security_issues": sum(1 for f in findings if f["category"] == "security"),
                "architecture_issues": sum(1 for f in findings if f["category"] == "architecture"),
            },
            raw_security=security_result,
            raw_architecture=architecture_result,
        )

        report_path = REPORTS_DIR / f"{job_id}.json"
        report_path.write_text(json.dumps(report.model_dump(), indent=2, default=str))

        status.status = "completed"
        status.progress = 100
        status.report_url = f"/report/{job_id}"

    except Exception as e:
        status.status = "failed"
        status.error = str(e)

    finally:
        # Clean up cloned repos to save disk space
        if target.startswith("http"):
            await cleanup_repo(target)


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
