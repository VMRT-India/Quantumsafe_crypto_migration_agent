"""
qsma.analyzer.core
==================
Parses source files into language-specific ASTs and extracts structural
information (imports, call sites) for all supported languages.
"""

from __future__ import annotations

import ast
import logging
from typing import Any

from qsma.utils.models import (
    AnalysisResult,
    CallSite,
    CodebaseSnapshot,
    ImportRef,
    ParsedFile,
)

logger = logging.getLogger(__name__)


def _get_tree_sitter_parser(language: str) -> Any:
    """Lazily loads and returns a tree-sitter Parser configured for the given language."""
    try:
        from tree_sitter import Language, Parser

        lang_map = {
            "python": ("tree_sitter_python", "python"),
            "java": ("tree_sitter_java", "java"),
            "go": ("tree_sitter_go", "go"),
            "c": ("tree_sitter_c", "c"),
            "rust": ("tree_sitter_rust", "rust"),
        }

        if language not in lang_map:
            logger.warning(f"Unsupported language for tree-sitter: {language}")
            return None

        module_name, _lang_name = lang_map[language]
        lang_module = __import__(module_name)
        language_obj = Language(lang_module.language())
        parser = Parser(language_obj)
        return parser
    except ImportError:
        logger.error(f"tree-sitter grammar for '{language}' not installed.")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize tree-sitter parser for '{language}': {e}")
        return None


def _extract_python_structures(
    content: str, ts_tree: Any
) -> tuple[list[ImportRef], list[CallSite]]:
    """Extracts imports and call sites from Python code."""
    imports: list[ImportRef] = []
    calls: list[CallSite] = []

    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        ImportRef(
                            module=alias.name.split(".")[0],
                            qualified_name=alias.name,
                            alias=alias.asname,
                            line=node.lineno,
                            language="python",
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full = f"{module}.{alias.name}" if module else alias.name
                    imports.append(
                        ImportRef(
                            module=module.split(".")[0] if module else alias.name,
                            qualified_name=full,
                            alias=alias.asname,
                            line=node.lineno,
                            language="python",
                        )
                    )
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name:
                    calls.append(
                        CallSite(
                            function_name=func_name,
                            arguments=[str(arg) for arg in node.args[:3]],
                            line=node.lineno,
                            enclosing_function=None,
                            language="python",
                        )
                    )
    except SyntaxError:
        logger.warning("Failed to parse Python file with ast.")

    return imports, calls


def _extract_generic_structures(
    content: str, language: str, ts_tree: Any
) -> tuple[list[ImportRef], list[CallSite]]:
    """Placeholder for Java, Go, C, Rust extraction."""
    logger.debug(f"Generic extraction for {language} is a stub in Phase 1.")
    return [], []


def analyze_codebase(snapshot: CodebaseSnapshot) -> AnalysisResult:
    """Main entry point for the Analyzer module."""
    logger.info(f"Starting analysis of {snapshot.file_count} files...")

    parsed_files: list[ParsedFile] = []
    import_index: dict[str, list[ImportRef]] = {}

    for source_file in snapshot.files:
        logger.debug(f"Analyzing: {source_file.path}")

        ts_tree = None
        cst_tree = None
        imports: list[ImportRef] = []
        call_sites: list[CallSite] = []

        parser = _get_tree_sitter_parser(source_file.language)
        if parser:
            try:
                ts_tree = parser.parse(bytes(source_file.content, "utf8"))
            except Exception as e:
                logger.warning(f"tree-sitter parse failed for {source_file.path}: {e}")

        if source_file.language == "python":
            try:
                import libcst as cst

                cst_tree = cst.parse_module(source_file.content)
            except Exception as e:
                logger.warning(f"libcst parse failed for {source_file.path}: {e}")

        if source_file.language == "python":
            imports, call_sites = _extract_python_structures(source_file.content, ts_tree)
        else:
            imports, call_sites = _extract_generic_structures(
                source_file.content, source_file.language, ts_tree
            )

        for imp in imports:
            import_index.setdefault(imp.module, []).append(imp)

        parsed_files.append(
            ParsedFile(
                path=source_file.path,
                language=source_file.language,
                ts_tree=ts_tree,
                cst_tree=cst_tree,
                imports=imports,
                call_sites=call_sites,
            )
        )

    logger.info(f"Analysis complete. Processed {len(parsed_files)} files.")
    return AnalysisResult(parsed_files=parsed_files, import_index=import_index)
