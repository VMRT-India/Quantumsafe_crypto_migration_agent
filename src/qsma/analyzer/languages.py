"""
qsma.analyzer.languages
========================
tree-sitter language bindings loader.

We use the individual ``tree-sitter-<lang>`` PyPI packages (e.g.
``tree-sitter-python``, ``tree-sitter-java``) rather than the monolithic
``tree-sitter-languages`` bundle.

Rationale
---------
The individual packages (``tree-sitter-python>=0.21``, etc.) are already
listed as dependencies in ``pyproject.toml`` and ship pre-compiled wheels.
They expose a ``language()`` function that returns the Language object
directly, making them trivially composable.  The monolithic
``tree-sitter-languages`` bundle is convenient but less maintainable — it
bundles grammars at a fixed version and is not yet available for all
tree-sitter >=0.22 ABIs.  The per-package approach is also the one used in
the official tree-sitter Python documentation.
"""

from __future__ import annotations

import logging
from functools import cache

import tree_sitter_c as tsc
import tree_sitter_go as tsgo
import tree_sitter_java as tsjava
import tree_sitter_python as tspython
import tree_sitter_rust as tsrust
from tree_sitter import Language, Parser

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language singletons
# ---------------------------------------------------------------------------


@cache
def get_language(lang: str) -> Language | None:
    """Return the tree-sitter Language object for the given language string."""
    _MAP = {
        "python": tspython.language,
        "java": tsjava.language,
        "go": tsgo.language,
        "c": tsc.language,
        "rust": tsrust.language,
    }
    factory = _MAP.get(lang)
    if factory is None:
        logger.warning("No tree-sitter grammar for language: %s", lang)
        return None
    try:
        return Language(factory())
    except Exception:
        logger.exception("Failed to load tree-sitter grammar for %s", lang)
        return None


def get_parser(lang: str) -> Parser | None:
    """Return a ready-to-use tree-sitter Parser for the given language, or None."""
    language = get_language(lang)
    if language is None:
        return None
    return Parser(language)
