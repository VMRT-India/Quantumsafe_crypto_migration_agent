"""
qsma.ingestion.walker
=====================
Recursive filesystem walker that collects source files into a CodebaseSnapshot.

Responsibilities
----------------
- Walk the target path recursively, honouring .gitignore (via pathspec) and a
  configurable exclude-patterns list.
- Filter to allowed file extensions only.
- Skip binary files and files that exceed max_file_size.
- Produce a deterministic, lexicographically ordered CodebaseSnapshot.
- No parsing, AST, or analysis logic lives here.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pathspec

from qsma.utils.models import CodebaseSnapshot, IngestionConfig, SourceFile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extension → language mapping
# Add new languages here; the rest of the pipeline picks them up automatically.
# ---------------------------------------------------------------------------
_EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".rs": "rust",
}


def _detect_language(path: Path) -> str:
    """Return a language string for a given file path, or 'unknown'."""
    return _EXT_TO_LANGUAGE.get(path.suffix.lower(), "unknown")


def _is_binary(content: bytes) -> bool:
    """Heuristic: treat a file as binary if it contains a NUL byte in the first 8 KB."""
    return b"\x00" in content[:8192]


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:  # type: ignore[type-arg]
    """Load .gitignore from the project root, if present."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return None
    try:
        patterns = gitignore.read_text(encoding="utf-8").splitlines()
        return pathspec.PathSpec.from_lines("gitignore", patterns)
    except OSError:
        logger.warning("Could not read .gitignore at %s", gitignore)
        return None


def _matches_exclude(rel_str: str, exclude_patterns: list[str]) -> bool:
    """Return True if the relative path string matches any exclude glob pattern."""
    spec = pathspec.PathSpec.from_lines("gitignore", exclude_patterns)
    return bool(spec.match_file(rel_str))


def collect_snapshot(
    target_path: Path,
    config: IngestionConfig | None = None,
) -> CodebaseSnapshot:
    """
    Walk ``target_path`` and collect all matching source files.

    Parameters
    ----------
    target_path:
        Root directory (or single file) to walk.
    config:
        Ingestion configuration; defaults are applied if None.

    Returns
    -------
    CodebaseSnapshot
        Deterministic, lexicographically ordered snapshot.
    """
    if config is None:
        config = IngestionConfig()

    target_path = target_path.resolve()

    if target_path.is_file():
        # Single-file mode — wrap in a snapshot directly.
        files = _collect_single_file(target_path, target_path.parent, config)
        return CodebaseSnapshot(
            root_path=target_path.parent,
            files=files,
            file_count=len(files),
        )

    gitignore_spec: pathspec.PathSpec | None = (  # type: ignore[type-arg]
        _load_gitignore(target_path) if config.respect_gitignore else None
    )

    collected: list[SourceFile] = []
    allowed_exts = {ext.lower() for ext in config.extensions}

    for file_path in sorted(target_path.rglob("*")):
        if not file_path.is_file():
            continue

        rel = file_path.relative_to(target_path)
        rel_str = rel.as_posix()

        # Exclude patterns check
        if _matches_exclude(rel_str, config.exclude_patterns):
            logger.debug("Excluded by pattern: %s", rel_str)
            continue

        # .gitignore check
        if gitignore_spec and gitignore_spec.match_file(rel_str):
            logger.debug("Excluded by .gitignore: %s", rel_str)
            continue

        # Extension filter
        if file_path.suffix.lower() not in allowed_exts:
            continue

        # Size check
        try:
            size = file_path.stat().st_size
        except OSError:
            logger.warning("Could not stat %s — skipping", file_path)
            continue

        if size > config.max_file_size:
            logger.info("Skipping oversized file (%d bytes): %s", size, file_path)
            continue

        # Binary check
        try:
            raw = file_path.read_bytes()
        except OSError:
            logger.warning("Could not read %s — skipping", file_path)
            continue

        if _is_binary(raw):
            logger.debug("Skipping binary file: %s", file_path)
            continue

        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            logger.debug("Skipping non-UTF-8 file: %s", file_path)
            continue

        language = _detect_language(file_path)
        collected.append(
            SourceFile(
                path=file_path,
                content=content,
                language=language,
                size_bytes=size,
            )
        )

    return CodebaseSnapshot(
        root_path=target_path,
        files=collected,
        file_count=len(collected),
    )


def _collect_single_file(
    file_path: Path,
    root: Path,
    config: IngestionConfig,
) -> list[SourceFile]:
    """Collect a single file, applying size and binary checks."""
    allowed_exts = {ext.lower() for ext in config.extensions}
    if file_path.suffix.lower() not in allowed_exts:
        return []
    try:
        size = file_path.stat().st_size
        if size > config.max_file_size:
            return []
        raw = file_path.read_bytes()
        if _is_binary(raw):
            return []
        content = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    return [
        SourceFile(
            path=file_path,
            content=content,
            language=_detect_language(file_path),
            size_bytes=size,
        )
    ]
