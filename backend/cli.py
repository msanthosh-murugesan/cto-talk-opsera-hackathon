"""
Code Guardian powered by Santhosh — CLI Interface
====================================================
By Santhosh Murugesan, Full Creative Pvt.Ltd.
Run security + architecture scans directly from the command line.

Usage:
    python cli.py https://github.com/user/repo
    python cli.py ./my-project --mock
    python cli.py ./my-project --output report.json
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent dir to path so imports work when running this file directly
sys.path.insert(0, str(Path(__file__).parent))

from agents.security_agent import run_security_scan
from agents.architecture_agent import run_architecture_review
from parsers.normalizer import normalize_and_score
from utils.repo_loader import clone_or_locate_repo, cleanup_repo
from utils.score_calculator import calculate_scores


# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    ORANGE = "\033[93m"
    YELLOW = "\033[33m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    DIM = "\033[2m"


SEVERITY_COLORS = {
    "critical": Colors.RED,
    "high": Colors.ORANGE,
    "medium": Colors.YELLOW,
    "low": Colors.DIM,
}


def print_banner():
    """Display the tool's ASCII art banner."""
    print(f"""{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ⛨  CODE GUARDIAN powered by Santhosh                   ║
    ║        Security & Architecture Scanner                    ║
    ║        By Santhosh Murugesan, Full Creative Pvt.Ltd.      ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.RESET}""")


def print_score_bar(label: str, score: int, width: int = 30):
    """Render a visual score bar in the terminal."""
    filled = int(width * score / 100)
    empty = width - filled

    if score >= 80:
        color = Colors.GREEN
    elif score >= 60:
        color = Colors.YELLOW
    elif score >= 40:
        color = Colors.ORANGE
    else:
        color = Colors.RED

    bar = f"{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.RESET}"
    print(f"    {label}: {bar} {color}{score}/100{Colors.RESET}")


def print_finding(finding: dict, index: int):
    """Pretty-print a single finding."""
    severity = finding["severity"]
    color = SEVERITY_COLORS.get(severity, Colors.RESET)
    badge = f"{color}[{severity.upper()}]{Colors.RESET}"
    category = "🔒" if finding["category"] == "security" else "🏗️"

    print(f"\n  {category} {badge} {Colors.BOLD}{finding['title']}{Colors.RESET}")

    if finding.get("file_path"):
        loc = finding["file_path"]
        if finding.get("line_number"):
            loc += f":{finding['line_number']}"
        print(f"     📁 {Colors.DIM}{loc}{Colors.RESET}")

    if finding.get("rule_id"):
        print(f"     🏷️  {Colors.DIM}{finding['rule_id']}{Colors.RESET}")

    print(f"     {finding['description'][:200]}")

    if finding.get("fix_suggestion"):
        print(f"     {Colors.GREEN}💡 Fix: {finding['fix_suggestion'][:200]}{Colors.RESET}")


async def main():
    parser = argparse.ArgumentParser(
        description="Code Guardian powered by Santhosh — Security & Architecture Scanner"
    )
    parser.add_argument("target", help="GitHub URL or local project path to scan")
    parser.add_argument("--mock", action="store_true", help="Use mock agents for testing")
    parser.add_argument("--output", "-o", help="Save JSON report to file")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only output JSON")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()
        print(f"  🎯 Target: {Colors.BOLD}{args.target}{Colors.RESET}")
        if args.mock:
            print(f"  ⚠️  Running in {Colors.YELLOW}MOCK MODE{Colors.RESET}")
        print()

    # Step 1: Resolve target
    if not args.quiet:
        print(f"  📂 Resolving target...", end="", flush=True)

    try:
        repo_path = await clone_or_locate_repo(args.target)
        if not args.quiet:
            print(f" ✅")
    except ValueError as e:
        print(f"\n  ❌ {Colors.RED}{e}{Colors.RESET}")
        sys.exit(1)

    # Step 2: Run both agents concurrently
    if not args.quiet:
        print(f"  🔍 Running Security Agent...", end="", flush=True)
        print(f"\n  🏗️  Running Architecture Agent...", end="", flush=True)
        print(f"\n  ⏳ Both agents running in parallel...", end="", flush=True)

    security_result, architecture_result = await asyncio.gather(
        run_security_scan(repo_path, mock=args.mock),
        run_architecture_review(repo_path, mock=args.mock),
    )

    if not args.quiet:
        print(f" ✅")

    # Step 3: Normalize and score
    if not args.quiet:
        print(f"  📊 Analyzing results...", end="", flush=True)

    findings = normalize_and_score(security_result, architecture_result)
    scores = calculate_scores(findings)

    if not args.quiet:
        print(f" ✅\n")

    # Build report
    report = {
        "target": args.target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scores": scores.model_dump(),
        "summary": {
            "total_issues": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "security_issues": sum(1 for f in findings if f["category"] == "security"),
            "architecture_issues": sum(1 for f in findings if f["category"] == "architecture"),
        },
        "findings": findings,
    }

    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(report, indent=2, default=str))
        if not args.quiet:
            print(f"  💾 Report saved to: {Colors.CYAN}{args.output}{Colors.RESET}\n")

    # Output
    if args.quiet:
        print(json.dumps(report, indent=2, default=str))
    else:
        # Print scores
        print(f"  {Colors.BOLD}═══ HEALTH SCORES ═══{Colors.RESET}\n")
        print_score_bar("Security     ", scores.security_score)
        print_score_bar("Architecture ", scores.architecture_score)
        print_score_bar("Combined     ", scores.combined_score)

        # Print summary
        summary = report["summary"]
        print(f"\n  {Colors.BOLD}═══ SUMMARY ═══{Colors.RESET}")
        print(f"    Total issues: {summary['total_issues']}")
        print(f"    {Colors.RED}Critical: {summary['critical']}{Colors.RESET}  |  "
              f"{Colors.ORANGE}High: {summary['high']}{Colors.RESET}  |  "
              f"{Colors.YELLOW}Medium: {summary['medium']}{Colors.RESET}  |  "
              f"{Colors.DIM}Low: {summary['low']}{Colors.RESET}")
        print(f"    🔒 Security: {summary['security_issues']}  |  "
              f"🏗️  Architecture: {summary['architecture_issues']}")

        # Print findings
        print(f"\n  {Colors.BOLD}═══ FINDINGS ═══{Colors.RESET}")
        for i, finding in enumerate(findings):
            print_finding(finding, i)

        print(f"\n  {Colors.DIM}{'─' * 55}{Colors.RESET}")
        print(f"  🚀 Start the dashboard: cd backend && uvicorn main:app --reload")
        print(f"  📖 API docs: http://localhost:8000/docs\n")

    # Cleanup
    if args.target.startswith("http"):
        await cleanup_repo(args.target)


if __name__ == "__main__":
    asyncio.run(main())
