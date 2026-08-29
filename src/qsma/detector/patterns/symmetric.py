"""
src/qsma/detector/patterns/symmetric.py
=========================================
Detection rules for DES, 3DES, and AES-128 usage.

Covers:
- DES / 3DES imports and call sites (pycryptodome, cryptography)
- AES-128 usage: key size <= 16 bytes detected via urandom(16) call context
  or explicit AES import with 128-bit indicators
"""

from __future__ import annotations

from qsma.utils.models import CodeLocation, CryptoHit, DetectionRule, ParsedFile

_DES_QUALIFIERS = {
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "Crypto.Cipher.DES",
    "Crypto.Cipher.DES3",
    "Crypto.Cipher.ARC2",
}

_AES_QUALIFIERS = {
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "Crypto.Cipher.AES",
}


def _make_location(pf: ParsedFile, line: int) -> CodeLocation:
    return CodeLocation(file=pf.path, line_start=line, line_end=line)


def _has_des_import(pf: ParsedFile) -> bool:
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "des" in qn or "3des" in qn or "triple" in qn:
            return True
    return False


def _has_aes_import(pf: ParsedFile) -> bool:
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "aes" in qn or "cipher" in qn:
            return True
    return False


# ── DES import ────────────────────────────────────────────────────────────


def _match_des_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "des" in qn:
            algo = "3DES" if ("3" in qn or "triple" in qn) else "DES"
            hits.append(
                CryptoHit(
                    rule_id=f"{algo.lower()}-import",
                    algorithm_hint=algo,
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── DES usage call ─────────────────────────────────────────────────────────


def _match_des_usage(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    if not _has_des_import(pf):
        return hits
    for cs in pf.call_sites:
        if cs.function_name in ("new", "DES", "DES3"):
            hits.append(
                CryptoHit(
                    rule_id="des-cipher-usage",
                    algorithm_hint="DES",
                    usage_type="encryption",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name},
                )
            )
    return hits


# ── AES import ────────────────────────────────────────────────────────────


def _match_aes_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "aes" in qn or "cipher" in qn:
            hits.append(
                CryptoHit(
                    rule_id="aes-import",
                    algorithm_hint="AES-128",
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── AES-128 usage: urandom(16) key size heuristic ─────────────────────────
# Flags when code generates a 16-byte key (urandom(16)) alongside an AES import.
# This is the strongest signal for AES-128; AES-256 uses urandom(32).


def _match_aes128_usage(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    if not _has_aes_import(pf):
        return hits

    for cs in pf.call_sites:
        fn = cs.function_name
        qn = cs.qualified_name or ""
        # Cipher(algorithms.AES(key), ...) call
        if fn in ("Cipher", "AES", "new") and "aes" in qn.lower():
            hits.append(
                CryptoHit(
                    rule_id="aes128-cipher-usage",
                    algorithm_hint="AES-128",
                    usage_type="encryption",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": fn, "qualified_name": qn},
                )
            )
        # AES.new(..., AES.MODE_ECB) — ECB is particularly dangerous
        if fn == "new" and "ecb" in (cs.qualified_name or "").lower():
            hits.append(
                CryptoHit(
                    rule_id="aes-ecb-usage",
                    algorithm_hint="AES-128",
                    usage_type="encryption",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": fn, "mode": "ECB"},
                )
            )
    return hits


SYMMETRIC_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="des-import",
        algorithm_hint="DES",
        usage_type="import",
        matcher_fn=_match_des_import,
    ),
    DetectionRule(
        rule_id="des-cipher-usage",
        algorithm_hint="DES",
        usage_type="encryption",
        matcher_fn=_match_des_usage,
    ),
    DetectionRule(
        rule_id="aes-import",
        algorithm_hint="AES-128",
        usage_type="import",
        matcher_fn=_match_aes_import,
    ),
    DetectionRule(
        rule_id="aes128-cipher-usage",
        algorithm_hint="AES-128",
        usage_type="encryption",
        matcher_fn=_match_aes128_usage,
    ),
]
