"""
qsma.analyzer.parser
====================
Parse source files with tree-sitter (>=0.24) and (for Python) libcst, then
extract structural information into ParsedFile objects.

tree-sitter 0.24+ API note
---------------------------
The `Language.query()` method was removed in tree-sitter 0.24.  Queries must
be constructed via `Query(language, query_string)` and executed through a
`QueryCursor`:

    cursor = QueryCursor(Query(lang, query_str))
    matches = cursor.matches(root)   # returns list[(pattern_index, captures_dict)]
    # captures_dict: {capture_name: list[Node]}

This module exclusively uses the `QueryCursor` path.
"""

from __future__ import annotations

import logging
from pathlib import Path

import libcst
from tree_sitter import Language, Node, Query, QueryCursor

from qsma.analyzer.crypto_imports import is_crypto_import
from qsma.analyzer.languages import get_language, get_parser
from qsma.utils.models import AnalysisResult, CallSite, CodebaseSnapshot, ImportRef, ParsedFile

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _text(node: Node) -> str:
    """Return the source text of a tree-sitter node."""
    return node.text.decode("utf-8") if node.text else ""


def _run_query(
    lang: Language,
    query_str: str,
    root: Node,
) -> list[tuple[int, dict[str, list[Node]]]]:
    """
    Execute a tree-sitter Query via QueryCursor.

    Returns a list of (pattern_index, {capture_name: [Node, …]}) tuples.
    Returns [] on any error so callers never crash on malformed queries.
    """
    try:
        q = Query(lang, query_str)
        cursor = QueryCursor(q)
        return cursor.matches(root)
    except Exception:
        logger.debug("Query execution failed for %s", query_str[:60], exc_info=True)
        return []


def _nodes(captures: dict[str, list[Node]], name: str) -> list[Node]:
    """Safely retrieve node list from a captures dict."""
    val = captures.get(name, [])
    if isinstance(val, list):
        return val
    return [val]  # defensive: single node rather than list


# ---------------------------------------------------------------------------
# Python-specific extraction
# ---------------------------------------------------------------------------

_PY_IMPORTS_PLAIN = """
(import_statement
  name: [
    (dotted_name) @module
    (aliased_import name: (dotted_name) @module)
  ])
"""

_PY_IMPORTS_FROM = """
(import_from_statement
  module_name: (dotted_name) @module)
"""

_PY_IMPORTS_FROM_RELATIVE = """
(import_from_statement
  module_name: (relative_import) @module)
"""

_PY_FUNCTIONS = """
(function_definition name: (identifier) @func_name)
"""

_PY_CLASSES = """
(class_definition name: (identifier) @class_name)
"""

_PY_CALLS_ATTR = """
(call function: (attribute object: (_) @obj attribute: (identifier) @attr))
"""

_PY_CALLS_PLAIN = """
(call function: (identifier) @func)
"""


def _extract_python(source: str, path: Path) -> ParsedFile:
    """Parse a Python source file and extract structural information."""
    parser = get_parser("python")
    if parser is None:
        return ParsedFile(path=path, language="python")

    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    lang = get_language("python")
    assert lang is not None

    imports: list[ImportRef] = []
    call_sites: list[CallSite] = []
    function_defs: dict[str, int] = {}
    class_defs: dict[str, int] = {}

    # ── plain imports: import foo  /  import foo as bar ────────────────────
    for _, caps in _run_query(lang, _PY_IMPORTS_PLAIN, root):
        for node in _nodes(caps, "module"):
            mod = _text(node)
            top = mod.split(".")[0]
            imports.append(
                ImportRef(
                    module=top,
                    qualified_name=mod,
                    line=node.start_point[0] + 1,
                    language="python",
                    is_crypto=is_crypto_import(top, "python"),
                )
            )

    # ── from … import … ────────────────────────────────────────────────────
    for _, caps in _run_query(lang, _PY_IMPORTS_FROM, root):
        for node in _nodes(caps, "module"):
            mod = _text(node)
            top = mod.split(".")[0]
            imports.append(
                ImportRef(
                    module=top,
                    qualified_name=mod,
                    line=node.start_point[0] + 1,
                    language="python",
                    is_crypto=is_crypto_import(top, "python"),
                )
            )

    # ── from .rel import … ─────────────────────────────────────────────────
    for _, caps in _run_query(lang, _PY_IMPORTS_FROM_RELATIVE, root):
        for node in _nodes(caps, "module"):
            mod = _text(node).lstrip(".")
            top = mod.split(".")[0] if mod else ""
            if top:
                imports.append(
                    ImportRef(
                        module=top,
                        qualified_name=mod,
                        line=node.start_point[0] + 1,
                        language="python",
                        is_crypto=is_crypto_import(top, "python"),
                    )
                )

    # ── function definitions ───────────────────────────────────────────────
    for _, caps in _run_query(lang, _PY_FUNCTIONS, root):
        for node in _nodes(caps, "func_name"):
            function_defs[_text(node)] = node.start_point[0] + 1

    # ── class definitions ──────────────────────────────────────────────────
    for _, caps in _run_query(lang, _PY_CLASSES, root):
        for node in _nodes(caps, "class_name"):
            class_defs[_text(node)] = node.start_point[0] + 1

    # ── attribute calls: obj.method(…) ────────────────────────────────────
    for _, caps in _run_query(lang, _PY_CALLS_ATTR, root):
        obj_nodes = _nodes(caps, "obj")
        attr_nodes = _nodes(caps, "attr")
        for obj_n, attr_n in zip(obj_nodes, attr_nodes, strict=False):
            obj_text = _text(obj_n)
            attr_text = _text(attr_n)
            call_sites.append(
                CallSite(
                    function_name=attr_text,
                    qualified_name=f"{obj_text}.{attr_text}",
                    line=attr_n.start_point[0] + 1,
                    language="python",
                )
            )

    # ── plain calls: func(…) ──────────────────────────────────────────────
    for _, caps in _run_query(lang, _PY_CALLS_PLAIN, root):
        for node in _nodes(caps, "func"):
            call_sites.append(
                CallSite(
                    function_name=_text(node),
                    qualified_name=_text(node),
                    line=node.start_point[0] + 1,
                    language="python",
                )
            )

    # ── intra-file call graph ──────────────────────────────────────────────
    intra_file_calls: dict[str, list[str]] = {}
    for cs in call_sites:
        callee = cs.qualified_name or cs.function_name
        caller = "<module>"
        intra_file_calls.setdefault(callee, [])
        if caller not in intra_file_calls[callee]:
            intra_file_calls[callee].append(caller)

    # ── libcst CST tree ────────────────────────────────────────────────────
    cst_tree = None
    try:
        cst_tree = libcst.parse_module(source)
    except libcst.ParserSyntaxError:
        logger.debug("libcst could not parse %s", path)

    return ParsedFile(
        path=path,
        language="python",
        ts_tree=tree,
        cst_tree=cst_tree,
        imports=imports,
        call_sites=call_sites,
        intra_file_calls=intra_file_calls,
        function_defs=function_defs,
        class_defs=class_defs,
    )


# ---------------------------------------------------------------------------
# Generic extraction for non-Python languages
# ---------------------------------------------------------------------------

_GENERIC_QUERIES: dict[str, dict[str, str]] = {
    "java": {
        "imports": "(import_declaration (scoped_identifier) @module)",
        "functions": "(method_declaration name: (identifier) @func_name)",
        "classes": "(class_declaration name: (identifier) @class_name)",
        "calls": "(method_invocation name: (identifier) @func)",
    },
    "go": {
        "imports": "(import_spec path: (interpreted_string_literal) @module)",
        "functions": "(function_declaration name: (identifier) @func_name)",
        "classes": "(type_declaration (type_spec name: (type_identifier) @class_name))",
        "calls_plain": "(call_expression function: (identifier) @func)",
        "calls_sel": "(call_expression function: (selector_expression field: (field_identifier) @func))",
    },
    "c": {
        "imports": "(preproc_include path: [(system_lib_string) @module (string_literal) @module])",
        "functions": "(function_definition declarator: (function_declarator declarator: (identifier) @func_name))",
        "classes": "(struct_specifier name: (type_identifier) @class_name)",
        "calls": "(call_expression function: (identifier) @func)",
    },
    "rust": {
        "imports": "(use_declaration argument: (_) @module)",
        "functions": "(function_item name: (identifier) @func_name)",
        "classes": "(struct_item name: (type_identifier) @class_name)",
        "calls_plain": "(call_expression function: (identifier) @func)",
        "calls_scoped": "(call_expression function: (scoped_identifier name: (identifier) @func))",
    },
}


def _extract_generic(source: str, path: Path, language: str) -> ParsedFile:
    """Parse a non-Python source file with tree-sitter only."""
    parser = get_parser(language)
    if parser is None:
        logger.info("No parser available for %s — returning empty ParsedFile", language)
        return ParsedFile(path=path, language=language)

    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    lang = get_language(language)
    if lang is None:
        return ParsedFile(path=path, language=language, ts_tree=tree)

    lang_queries = _GENERIC_QUERIES.get(language, {})
    imports: list[ImportRef] = []
    call_sites: list[CallSite] = []
    function_defs: dict[str, int] = {}
    class_defs: dict[str, int] = {}

    import_q = lang_queries.get("imports")
    if import_q:
        for _, caps in _run_query(lang, import_q, root):
            for node in _nodes(caps, "module"):
                raw = _text(node).strip('"<>')
                top = raw.split("/")[0].split(".")[0]
                imports.append(
                    ImportRef(
                        module=top,
                        qualified_name=raw,
                        line=node.start_point[0] + 1,
                        language=language,
                        is_crypto=is_crypto_import(raw, language),
                    )
                )

    func_q = lang_queries.get("functions")
    if func_q:
        for _, caps in _run_query(lang, func_q, root):
            for node in _nodes(caps, "func_name"):
                function_defs[_text(node)] = node.start_point[0] + 1

    class_q = lang_queries.get("classes")
    if class_q:
        for _, caps in _run_query(lang, class_q, root):
            for node in _nodes(caps, "class_name"):
                class_defs[_text(node)] = node.start_point[0] + 1

    # calls — handle multiple call query variants
    for qkey in ("calls", "calls_plain", "calls_sel", "calls_scoped"):
        call_q = lang_queries.get(qkey)
        if call_q:
            for _, caps in _run_query(lang, call_q, root):
                for node in _nodes(caps, "func"):
                    call_sites.append(
                        CallSite(
                            function_name=_text(node),
                            line=node.start_point[0] + 1,
                            language=language,
                        )
                    )

    intra_file_calls: dict[str, list[str]] = {}
    for cs in call_sites:
        callee = cs.function_name
        intra_file_calls.setdefault(callee, [])
        if "<module>" not in intra_file_calls[callee]:
            intra_file_calls[callee].append("<module>")

    return ParsedFile(
        path=path,
        language=language,
        ts_tree=tree,
        imports=imports,
        call_sites=call_sites,
        intra_file_calls=intra_file_calls,
        function_defs=function_defs,
        class_defs=class_defs,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_file(source: str, path: Path, language: str) -> ParsedFile:
    """Parse a single source file and return a ParsedFile."""
    if language == "python":
        return _extract_python(source, path)
    return _extract_generic(source, path, language)


def analyse_snapshot(snapshot: CodebaseSnapshot) -> AnalysisResult:
    """
    Parse all files in a CodebaseSnapshot and return an AnalysisResult.

    Parameters
    ----------
    snapshot:
        The output of Ingestion.

    Returns
    -------
    AnalysisResult
        Per-file ParsedFile objects + flat import index across all files.
    """
    parsed_files: list[ParsedFile] = []
    import_index: dict[str, list[ImportRef]] = {}

    for source_file in snapshot.files:
        logger.debug("Parsing %s (%s)", source_file.path, source_file.language)
        pf = parse_file(source_file.content, source_file.path, source_file.language)
        parsed_files.append(pf)

        for imp in pf.imports:
            import_index.setdefault(imp.module, []).append(imp)

    return AnalysisResult(parsed_files=parsed_files, import_index=import_index)
