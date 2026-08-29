"""
qsma.ingestion.core
===================
Walks the target filesystem and collects source files for analysis.
Produces a reproducible, ordered CodebaseSnapshot.
"""

import logging
import os
from collections.abc import Iterator
from pathlib import Path

from qsma.utils.models import CodebaseSnapshot, IngestionConfig, SourceFile

logger = logging.getLogger(__name__)

# Binary file extensions to always skip
BINARY_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".o",
    ".a",
    ".lib",
    ".exe",
    ".dll",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
}


def _is_binary(path: Path) -> bool:
    """Quick check for binary files based on extension or null bytes."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except OSError:
        return True
    return False


def _detect_language(path: Path) -> str:
    """Map file extension to language identifier."""
    ext_map = {
        ".py": "python",
        ".java": "java",
        ".go": "go",
        ".c": "c",
        ".cpp": "c",
        ".h": "c",
        ".rs": "rust",
    }
    return ext_map.get(path.suffix.lower(), "unknown")


def _walk_files(root: Path, config: IngestionConfig) -> Iterator[Path]:
    """
    Recursively walk the directory, yielding valid file paths.
    Sorts output to ensure reproducible, ordered snapshots.
    """
    # Simple ignore logic for MVP (can be extended to parse .gitignore later)
    ignore_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox", ".mypy_cache"}

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]

        for filename in sorted(filenames):  # Sort for reproducibility
            file_path = Path(dirpath) / filename

            # Check exclusions
            if any(file_path.match(pat) for pat in config.exclude_patterns):
                continue

            # Check extensions
            if config.extensions and file_path.suffix.lower() not in config.extensions:
                continue

            # Check size
            try:
                if file_path.stat().st_size > config.max_file_size:
                    logger.debug(f"Skipping large file: {file_path}")
                    continue
            except OSError:
                continue

            # Check binary
            if _is_binary(file_path):
                continue

            yield file_path


def ingest_codebase(target_path: Path, config: IngestionConfig | None = None) -> CodebaseSnapshot:
    """
    Main entry point for the Ingestion module.
    Walks the filesystem and returns a CodebaseSnapshot.
    """
    if config is None:
        config = IngestionConfig()

    target_path = target_path.resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    logger.info(f"Starting ingestion for: {target_path}")

    files: list[SourceFile] = []

    for file_path in _walk_files(target_path, config):
        try:
            content = file_path.read_text(encoding="utf-8")
            language = _detect_language(file_path)

            files.append(SourceFile(path=file_path, content=content, language=language))
        except UnicodeDecodeError:
            logger.warning(f"Skipping file with encoding issues: {file_path}")
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")

    # Sort by path to guarantee deterministic ordering
    files.sort(key=lambda f: f.path)

    logger.info(f"Ingestion complete. Found {len(files)} valid source files.")

    return CodebaseSnapshot(root_path=target_path, files=files, file_count=len(files))
