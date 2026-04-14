"""
Repository Loader
==================
Handles resolving scan targets: cloning GitHub repos to a temp directory
or validating that a local path exists and is a valid project directory.
"""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

# Store cloned repos so we can clean them up later
_cloned_repos: dict[str, str] = {}


async def clone_or_locate_repo(target: str) -> str:
    """
    Resolve a scan target to a local file path.

    - If target is a GitHub URL → clone it to a temp directory
    - If target is a local path → validate it exists
    - Returns the absolute path to the project root

    Args:
        target: GitHub URL (https://github.com/...) or local filesystem path

    Returns:
        Absolute path to the project directory

    Raises:
        ValueError: If the target is invalid or unreachable
    """
    if target.startswith(("http://", "https://")):
        return await _clone_repo(target)
    else:
        return _validate_local_path(target)


async def _clone_repo(url: str) -> str:
    """Clone a GitHub repository to a temporary directory."""
    # Create a temp dir that persists until we explicitly clean it up
    clone_dir = tempfile.mkdtemp(prefix="codeguardian_")

    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", url, clone_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

        if process.returncode != 0:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise ValueError(f"Failed to clone repository: {stderr.decode().strip()}")

        _cloned_repos[url] = clone_dir
        return clone_dir

    except asyncio.TimeoutError:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise ValueError(f"Repository clone timed out after 60 seconds: {url}")


def _validate_local_path(path: str) -> str:
    """Ensure a local path exists and looks like a project directory."""
    resolved = Path(path).resolve()

    if not resolved.exists():
        raise ValueError(f"Path does not exist: {path}")

    if not resolved.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    # Sanity check: look for at least one source file
    source_extensions = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".rs"}
    has_source = any(
        f.suffix in source_extensions
        for f in resolved.rglob("*")
        if f.is_file() and "node_modules" not in f.parts
    )

    if not has_source:
        # Not a hard error — the project might just use an unusual language
        import sys
        print(f"[RepoLoader] Warning: no common source files found in {path}", file=sys.stderr)

    return str(resolved)


async def cleanup_repo(target: str):
    """Remove a cloned repository from disk."""
    if target in _cloned_repos:
        clone_dir = _cloned_repos.pop(target)
        shutil.rmtree(clone_dir, ignore_errors=True)
