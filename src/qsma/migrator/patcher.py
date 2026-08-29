"""
qsma.migrator.patcher
=====================
libcst-based source file patcher.

Takes the LLM-generated replacement code for a specific line range and
splices it back into the original source file, replacing only the lines
covered by the finding (line_start..line_end, 1-based inclusive).

libcst is used here purely as a file-write utility (ADR-003):
  - It parses the full source file to a CST.
  - The replacement block is inserted at the correct position.
  - The file is written back with all surrounding code, comments, and
    formatting preserved.

Atomic writes: write to a sibling .tmp file → os.replace() on success.
Dry-run: return the unified diff without writing anything.

Safety invariant:
  Code outside line_start..line_end is NEVER modified.
"""

from __future__ import annotations

import difflib
import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def apply_patch(
    source_path: Path,
    replacement_code: str,
    line_start: int,
    line_end: int,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """
    Replace lines [line_start, line_end] (1-based, inclusive) in *source_path*
    with *replacement_code*.

    Parameters
    ----------
    source_path       : absolute path to the Python file to patch
    replacement_code  : the transformed code block produced by the LLM
    line_start        : first line to replace (1-based)
    line_end          : last line to replace (1-based, inclusive)
    dry_run           : if True, return the diff but do NOT write the file

    Returns
    -------
    (success: bool, detail: str)
      success=True,  detail=unified_diff_string — on success
      success=False, detail=error_message       — on failure
    """
    try:
        original_source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"Cannot read {source_path}: {exc}"

    original_lines = original_source.splitlines(keepends=True)
    n = len(original_lines)

    # Validate range
    if line_start < 1 or line_end < line_start or line_end > n:
        return False, (
            f"Line range {line_start}–{line_end} is out of bounds "
            f"for file with {n} lines: {source_path}"
        )

    # Build replacement lines (ensure trailing newline on each line)
    replacement_lines = _normalise_lines(replacement_code)

    # Splice: keep lines before + replacement + lines after
    patched_lines = (
        original_lines[: line_start - 1]
        + replacement_lines
        + original_lines[line_end:]
    )
    patched_source = "".join(patched_lines)

    # Validate that the patched result is valid Python syntax
    ok, syntax_err = _check_syntax(patched_source, source_path)
    if not ok:
        return False, f"Patched code has a syntax error: {syntax_err}"

    # Produce unified diff (always — returned for logging + dry-run display)
    diff = "".join(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{source_path.name}",
            tofile=f"b/{source_path.name}",
            lineterm="",
        )
    )

    if dry_run:
        return True, diff

    # Atomic write: temp file in same directory → os.replace()
    try:
        dir_ = source_path.parent
        fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".qsma_tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(patched_source)
            os.replace(tmp_path, source_path)
        except Exception:
            # Clean up temp on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as exc:
        return False, f"Failed to write {source_path}: {exc}"

    logger.info("Patcher: wrote %s (lines %d–%d replaced)", source_path, line_start, line_end)
    return True, diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_lines(code: str) -> list[str]:
    """Split code into lines preserving newlines; ensure final newline."""
    if not code.endswith("\n"):
        code = code + "\n"
    return code.splitlines(keepends=True)


def _check_syntax(source: str, path: Path) -> tuple[bool, str]:
    """Return (True, "") if source is valid Python, else (False, error)."""
    try:
        compile(source, str(path), "exec")
        return True, ""
    except SyntaxError as exc:
        return False, str(exc)
