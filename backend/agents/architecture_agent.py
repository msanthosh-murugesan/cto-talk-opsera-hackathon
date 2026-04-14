"""
Architecture Agent Integration — Code Guardian powered by Santhosh
====================================================================
By Santhosh Murugesan, Full Creative Pvt.Ltd.

This module handles communication with the Architecture Agent.

In REAL mode: Invokes the agent to review code structure, detect
anti-patterns, evaluate coupling/cohesion, and suggest improvements for
scalability and maintainability.

In MOCK mode: Returns realistic sample data mirroring actual agent output
for development and demo purposes.
"""

import asyncio
import hashlib
import json
import os
import random
import subprocess
from pathlib import Path
from typing import Any


async def run_architecture_review(repo_path: str, mock: bool = False) -> dict[str, Any]:
    """
    Execute the Architecture Agent against the given codebase.

    Args:
        repo_path: Absolute path to the project directory to analyze
        mock: If True, return realistic sample data

    Returns:
        Raw agent output as a dictionary containing architecture findings
    """
    if mock:
        return _get_mock_architecture_results(repo_path)

    return await _invoke_opsera_architecture_agent(repo_path)


async def _invoke_opsera_architecture_agent(repo_path: str) -> dict[str, Any]:
    """
    Invoke the real Architecture Agent.

    The agent analyzes:
      - Module coupling and cohesion metrics
      - Design pattern usage and anti-patterns
      - Code complexity (cyclomatic, cognitive)
      - Dependency graph health
      - Layer separation and boundary violations
      - Configuration and infrastructure patterns
    """
    try:
        # Attempt CLI invocation
        result = await asyncio.to_thread(
            subprocess.run,
            [
                "opsera-agent", "architecture", "review",
                "--path", repo_path,
                "--format", "json",
                "--depth", "full",
                "--include-suggestions",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            return json.loads(result.stdout)

        return await _invoke_via_opsera_api(repo_path)

    except FileNotFoundError:
        print("[ArchitectureAgent] CLI not found, attempting API invocation...")
        return await _invoke_via_opsera_api(repo_path)

    except Exception as e:
        print(f"[ArchitectureAgent] Error during review: {e}")
        return {
            "agent": "opsera-architecture",
            "status": "error",
            "error": str(e),
            "findings": [],
        }


async def _invoke_via_opsera_api(repo_path: str) -> dict[str, Any]:
    """Fallback: invoke via REST API."""
    import aiohttp

    api_url = os.getenv("OPSERA_API_URL", "https://api.opsera.io/v1")
    api_key = os.getenv("OPSERA_API_KEY", "")

    if not api_key:
        print("[ArchitectureAgent] No API key. Returning empty results.")
        return {"agent": "opsera-architecture", "status": "no-api-key", "findings": []}

    files_payload = _collect_source_files(repo_path)

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{api_url}/agents/architecture/review",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"files": files_payload},
            timeout=aiohttp.ClientTimeout(total=120),
        ) as resp:
            return await resp.json()


def _collect_source_files(repo_path: str, max_files: int = 100) -> list[dict]:
    """Gather source files for API-based analysis."""
    source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".rs"}
    files = []
    repo = Path(repo_path)

    for fpath in repo.rglob("*"):
        if len(files) >= max_files:
            break
        if fpath.is_file() and fpath.suffix.lower() in source_extensions:
            if any(part in fpath.parts for part in ["node_modules", ".venv", "venv", "__pycache__", ".git"]):
                continue
            try:
                content = fpath.read_text(errors="ignore")[:50_000]
                files.append({"path": str(fpath.relative_to(repo)), "content": content})
            except Exception:
                continue

    return files


# ── Mock Data ──────────────────────────────────────────────────────────────────

# Dirs/files to skip
_SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", ".tox", "dist", "build", ".mypy_cache"}
_SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".rs"}

# Thresholds for analysis
_LARGE_FILE_LINES = 200
_LARGE_FILE_FUNCTIONS = 8
_HIGH_NESTING_DEPTH = 4


def _get_mock_architecture_results(repo_path: str) -> dict[str, Any]:
    """
    Analyze actual repo files for architecture patterns and anti-patterns.
    Produces different results per repo based on real code structure.
    """
    rng = random.Random()
    repo = Path(repo_path)
    findings = []
    finding_id = 1
    analyzed_files = 0

    file_stats = []  # (rel_path, line_count, function_count, import_count, max_indent)

    # Pass 1: Collect file-level metrics
    for fpath in repo.rglob("*"):
        if not fpath.is_file():
            continue
        if any(skip in fpath.parts for skip in _SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue

        analyzed_files += 1
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        lines = content.splitlines()
        rel_path = str(fpath.relative_to(repo))
        line_count = len(lines)

        # Count functions/methods
        func_count = sum(1 for l in lines if _is_function_def(l, fpath.suffix))
        # Count imports
        import_count = sum(1 for l in lines if _is_import(l, fpath.suffix))
        # Max indentation depth (proxy for nesting)
        max_indent = 0
        for l in lines:
            stripped = l.lstrip()
            if stripped:
                indent = len(l) - len(stripped)
                depth = indent // 4 if fpath.suffix == ".py" else indent // 2
                max_indent = max(max_indent, depth)

        file_stats.append((rel_path, line_count, func_count, import_count, max_indent, lines))

    # Pass 2: Detect architecture issues from metrics

    # Check for God Classes / large files
    for rel_path, line_count, func_count, import_count, max_indent, lines in file_stats:
        if line_count > _LARGE_FILE_LINES and func_count > _LARGE_FILE_FUNCTIONS:
            findings.append({
                "id": f"ARCH-{finding_id:03d}",
                "type": "anti-pattern", "pattern": "god-class", "severity": "high",
                "title": f"Large file with many responsibilities: {rel_path}",
                "description": f"This file has {line_count} lines and {func_count} functions/methods, suggesting it handles too many responsibilities. This violates the Single Responsibility Principle.",
                "file": rel_path, "line": 1,
                "metrics": {"lines": line_count, "methods": func_count, "dependencies": import_count},
                "suggestion": "Decompose into smaller, focused modules. Each module should have a single clear responsibility.",
                "confidence": round(rng.uniform(0.80, 0.95), 2),
            })
            finding_id += 1

    # Check for high nesting depth (complexity)
    for rel_path, line_count, func_count, import_count, max_indent, lines in file_stats:
        if max_indent >= _HIGH_NESTING_DEPTH:
            findings.append({
                "id": f"ARCH-{finding_id:03d}",
                "type": "complexity", "pattern": "high-complexity-function", "severity": "high",
                "title": f"Deep nesting detected in {rel_path}",
                "description": f"Maximum nesting depth of {max_indent} levels found. Deep nesting makes code hard to read, test, and maintain.",
                "file": rel_path, "line": 1,
                "metrics": {"nesting_depth": max_indent, "lines": line_count},
                "suggestion": "Use guard clauses and early returns to flatten nesting. Extract deeply nested blocks into separate functions.",
                "confidence": round(rng.uniform(0.80, 0.92), 2),
            })
            finding_id += 1

    # Check for circular-ish imports (files that import each other's directories)
    import_map = {}  # file -> set of imported modules
    for rel_path, _, _, _, _, lines in file_stats:
        imports = set()
        for l in lines:
            l_stripped = l.strip()
            if l_stripped.startswith(("from ", "import ")):
                # Extract the module path
                parts = l_stripped.replace("from ", "").replace("import ", "").split()
                if parts:
                    imports.add(parts[0].split(".")[0])
            elif "require(" in l_stripped:
                imports.add(l_stripped)
        import_map[rel_path] = imports

    # Check for files with many imports (tight coupling)
    for rel_path, _, _, import_count, _, lines in file_stats:
        if import_count > 10:
            findings.append({
                "id": f"ARCH-{finding_id:03d}",
                "type": "anti-pattern", "pattern": "tight-coupling", "severity": "medium",
                "title": f"High import count in {rel_path}",
                "description": f"This file has {import_count} imports, indicating tight coupling with many other modules. Changes to any dependency may require changes here.",
                "file": rel_path, "line": 1,
                "metrics": {"import_count": import_count},
                "suggestion": "Reduce coupling by introducing abstractions or splitting the file into focused modules with fewer dependencies.",
                "confidence": round(rng.uniform(0.75, 0.90), 2),
            })
            finding_id += 1

    # Check for scattered error handling
    total_try_blocks = 0
    files_with_try = 0
    for rel_path, _, _, _, _, lines in file_stats:
        try_count = sum(1 for l in lines if l.strip().startswith(("try:", "try {", "catch ", "except ")))
        if try_count > 0:
            files_with_try += 1
            total_try_blocks += try_count

    if total_try_blocks > 5 and files_with_try > 3:
        findings.append({
            "id": f"ARCH-{finding_id:03d}",
            "type": "design", "pattern": "missing-abstraction", "severity": "medium",
            "title": "Scattered error handling across codebase",
            "description": f"Found {total_try_blocks} try/catch blocks across {files_with_try} files. Without a centralized error handling strategy, error responses may be inconsistent.",
            "file": "project-wide", "line": None,
            "metrics": {"scattered_handlers": total_try_blocks, "files_affected": files_with_try},
            "suggestion": "Create a centralized error handler middleware and a custom exception hierarchy for consistent error responses.",
            "confidence": round(rng.uniform(0.78, 0.88), 2),
        })
        finding_id += 1

    # Check for missing tests
    has_tests = any("test" in rel_path.lower() for rel_path, *_ in file_stats)
    if not has_tests and analyzed_files > 3:
        findings.append({
            "id": f"ARCH-{finding_id:03d}",
            "type": "structure", "pattern": "missing-tests", "severity": "high",
            "title": "No test files detected in project",
            "description": "No test files were found in the scanned directory. Automated tests are critical for maintaining code quality and preventing regressions.",
            "file": "project-wide", "line": None,
            "metrics": {"test_files": 0, "source_files": analyzed_files},
            "suggestion": "Add unit tests for critical business logic and integration tests for API endpoints.",
            "confidence": round(rng.uniform(0.85, 0.95), 2),
        })
        finding_id += 1

    # If no findings at all, generate baseline recommendations
    if not findings:
        findings = _get_baseline_architecture_findings(rng, analyzed_files)

    # Compute aggregate metrics
    all_lines = [lc for _, lc, *_ in file_stats]
    all_funcs = [fc for _, _, fc, *_ in file_stats]
    all_indents = [mi for _, _, _, _, mi, _ in file_stats]

    return {
        "agent": "code-guardian-architecture",
        "review_id": f"arch-{hashlib.sha256(repo_path.encode()).hexdigest()[:8]}-{rng.randint(1000, 9999)}",
        "status": "completed",
        "analyzed_files": analyzed_files,
        "review_duration_ms": rng.randint(2000, 7000),
        "metrics": {
            "avg_cyclomatic_complexity": round(sum(all_indents) / max(len(all_indents), 1) * 2.5, 1),
            "max_cyclomatic_complexity": max(all_indents, default=0) * 3,
            "avg_cognitive_complexity": round(sum(all_indents) / max(len(all_indents), 1) * 3.2, 1),
            "coupling_score": round(rng.uniform(0.3, 0.8), 2),
            "cohesion_score": round(rng.uniform(0.3, 0.7), 2),
            "dependency_depth": max((ic for _, _, _, ic, _, _ in file_stats), default=0),
        },
        "findings": findings,
    }


def _is_function_def(line: str, suffix: str) -> bool:
    """Check if a line is a function/method definition."""
    stripped = line.strip()
    if suffix == ".py":
        return stripped.startswith("def ") or stripped.startswith("async def ")
    if suffix in (".js", ".ts", ".jsx", ".tsx"):
        return ("function " in stripped or "=>" in stripped) and not stripped.startswith("//")
    if suffix in (".java", ".go", ".cs"):
        return "(" in stripped and ")" in stripped and "{" in stripped and not stripped.startswith("//")
    return False


def _is_import(line: str, suffix: str) -> bool:
    """Check if a line is an import statement."""
    stripped = line.strip()
    if suffix == ".py":
        return stripped.startswith("import ") or stripped.startswith("from ")
    if suffix in (".js", ".ts", ".jsx", ".tsx"):
        return stripped.startswith("import ") or "require(" in stripped
    if suffix in (".java",):
        return stripped.startswith("import ")
    if suffix == ".go":
        return stripped.startswith("import ")
    return False


def _get_baseline_architecture_findings(rng: random.Random, file_count: int) -> list[dict]:
    """Generate baseline architecture findings when no specific issues are detected."""
    return [{
        "id": "ARCH-001", "type": "design", "pattern": "review-needed", "severity": "low",
        "title": "Architecture review recommended",
        "description": f"Scanned {file_count} source files. Consider a periodic architecture review to ensure separation of concerns and maintainability.",
        "file": "project-wide", "line": None,
        "metrics": {"source_files": file_count},
        "suggestion": "Document the high-level architecture and review it quarterly.",
        "confidence": round(rng.uniform(0.70, 0.85), 2),
    }]
