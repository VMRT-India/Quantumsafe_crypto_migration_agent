"""
src/qsma/detector/patterns/hashing.py
======================================
Detection rules for MD5 and SHA-1 usage.

Covers:
- hashlib.md5() / hashlib.sha1() call sites
- Crypto.Hash.MD5 / Crypto.Hash.SHA import
- Direct md5 / sha1 function calls
"""

from __future__ import annotations

from qsma.utils.models import CodeLocation, CryptoHit, DetectionRule, ParsedFile

_MD5_KEYWORDS = {"md5"}
_SHA1_KEYWORDS = {"sha1", "sha-1"}


def _make_location(pf: ParsedFile, line: int) -> CodeLocation:
    return CodeLocation(file=pf.path, line_start=line, line_end=line)


def _has_hashlib_import(pf: ParsedFile) -> bool:
    return any(imp.module in ("hashlib", "hmac", "Crypto") for imp in pf.imports)


# ── MD5 import ─────────────────────────────────────────────────────────────


def _match_md5_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "md5" in qn:
            hits.append(
                CryptoHit(
                    rule_id="md5-import",
                    algorithm_hint="MD5",
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── SHA-1 import ───────────────────────────────────────────────────────────


def _match_sha1_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "sha1" in qn or "sha-1" in qn:
            hits.append(
                CryptoHit(
                    rule_id="sha1-import",
                    algorithm_hint="SHA-1",
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── MD5 call site ──────────────────────────────────────────────────────────


def _match_md5_call(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for cs in pf.call_sites:
        fn = cs.function_name.lower()
        qn = (cs.qualified_name or "").lower()
        if fn == "md5" or "md5" in qn:
            hits.append(
                CryptoHit(
                    rule_id="md5-hash-usage",
                    algorithm_hint="MD5",
                    usage_type="hashing",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name},
                )
            )
    return hits


# ── SHA-1 call site ────────────────────────────────────────────────────────


def _match_sha1_call(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for cs in pf.call_sites:
        fn = cs.function_name.lower()
        qn = (cs.qualified_name or "").lower()
        if fn in ("sha1", "sha_1") or "sha1" in qn:
            hits.append(
                CryptoHit(
                    rule_id="sha1-hash-usage",
                    algorithm_hint="SHA-1",
                    usage_type="hashing",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name},
                )
            )
    return hits


# ── hashlib.new("md5") / hashlib.new("sha1") ──────────────────────────────


def _match_hashlib_new_md5(pf: ParsedFile) -> list[CryptoHit]:
    """Detect hashlib.new('md5') and hashlib.md5() patterns."""
    hits: list[CryptoHit] = []
    if not _has_hashlib_import(pf):
        return hits
    for cs in pf.call_sites:
        fn = cs.function_name.lower()
        if fn in ("md5", "new") and any("md5" in arg.lower() for arg in cs.arguments):
            hits.append(
                CryptoHit(
                    rule_id="hashlib-md5-usage",
                    algorithm_hint="MD5",
                    usage_type="hashing",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name, "arguments": cs.arguments},
                )
            )
    return hits


HASHING_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="md5-import",
        algorithm_hint="MD5",
        usage_type="import",
        matcher_fn=_match_md5_import,
    ),
    DetectionRule(
        rule_id="sha1-import",
        algorithm_hint="SHA-1",
        usage_type="import",
        matcher_fn=_match_sha1_import,
    ),
    DetectionRule(
        rule_id="md5-hash-usage",
        algorithm_hint="MD5",
        usage_type="hashing",
        matcher_fn=_match_md5_call,
    ),
    DetectionRule(
        rule_id="sha1-hash-usage",
        algorithm_hint="SHA-1",
        usage_type="hashing",
        matcher_fn=_match_sha1_call,
    ),
    DetectionRule(
        rule_id="hashlib-md5-usage",
        algorithm_hint="MD5",
        usage_type="hashing",
        matcher_fn=_match_hashlib_new_md5,
    ),
]
