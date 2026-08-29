"""
qsma.analyzer.ts_queries
=========================
tree-sitter query strings for structural extraction, per language.

Each entry is a dict of named query groups::

    {
      "imports":    "<query string>",
      "functions":  "<query string>",
      "classes":    "<query string>",
      "calls":      "<query string>",
    }

The queries follow the tree-sitter S-expression syntax.  Captures are named
with ``@<name>`` anchors; the extractor functions in parser.py iterate over
captures by name.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
PYTHON_QUERIES: dict[str, str] = {
    # import foo  /  import foo as bar
    "imports_plain": """
        (import_statement
            name: (dotted_name) @module)
    """,
    # from foo.bar import baz  /  from foo import *
    "imports_from": """
        (import_from_statement
            module_name: (dotted_name) @module
            name: (_) @name)
    """,
    # from foo.bar import (baz, qux)  — relative imports
    "imports_from_relative": """
        (import_from_statement
            module_name: (relative_import) @module
            name: (_) @name)
    """,
    # def foo(...)  /  async def foo(...)
    "functions": """
        (function_definition
            name: (identifier) @func_name)
    """,
    # class Foo:
    "classes": """
        (class_definition
            name: (identifier) @class_name)
    """,
    # any call expression
    "calls": """
        (call
            function: [
                (identifier) @func
                (attribute
                    object: (_) @obj
                    attribute: (identifier) @attr)
            ])
    """,
}

# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------
JAVA_QUERIES: dict[str, str] = {
    "imports": """
        (import_declaration
            (scoped_identifier) @module)
    """,
    "functions": """
        (method_declaration
            name: (identifier) @func_name)
    """,
    "classes": """
        (class_declaration
            name: (identifier) @class_name)
    """,
    "calls": """
        (method_invocation
            name: (identifier) @func)
    """,
}

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------
GO_QUERIES: dict[str, str] = {
    # import "crypto/rsa"
    "imports": """
        (import_spec
            path: (interpreted_string_literal) @module)
    """,
    "functions": """
        (function_declaration
            name: (identifier) @func_name)
    """,
    "classes": """
        (type_declaration
            (type_spec
                name: (type_identifier) @class_name))
    """,
    "calls": """
        (call_expression
            function: [
                (identifier) @func
                (selector_expression
                    field: (field_identifier) @func)
            ])
    """,
}

# ---------------------------------------------------------------------------
# C
# ---------------------------------------------------------------------------
C_QUERIES: dict[str, str] = {
    # #include <openssl/rsa.h>  or  #include "local.h"
    "imports": """
        (preproc_include
            path: [
                (system_lib_string) @module
                (string_literal) @module
            ])
    """,
    "functions": """
        (function_definition
            declarator: (function_declarator
                declarator: (identifier) @func_name))
    """,
    "classes": """
        (struct_specifier
            name: (type_identifier) @class_name)
    """,
    "calls": """
        (call_expression
            function: (identifier) @func)
    """,
}

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------
RUST_QUERIES: dict[str, str] = {
    # use ring::aead;
    "imports": """
        (use_declaration
            argument: (_) @module)
    """,
    "functions": """
        (function_item
            name: (identifier) @func_name)
    """,
    "classes": """
        (struct_item
            name: (type_identifier) @class_name)
    """,
    "calls": """
        (call_expression
            function: [
                (identifier) @func
                (scoped_identifier
                    name: (identifier) @func)
                (field_expression
                    field: (field_identifier) @func)
            ])
    """,
}

LANGUAGE_QUERIES: dict[str, dict[str, str]] = {
    "python": PYTHON_QUERIES,
    "java": JAVA_QUERIES,
    "go": GO_QUERIES,
    "c": C_QUERIES,
    "rust": RUST_QUERIES,
}
