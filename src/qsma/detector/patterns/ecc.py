"""
src/qsma/detector/patterns/ecc.py
==================================
Detection rules for ECDSA / ECDH / DSA / DH usage.

Covers:
- Importing EC/DSA/DH modules
- Calling key generation functions for EC (ECDSA / ECDH)
- Calling key exchange (ECDH.exchange)
- Calling DSA / DH key generation and operations
"""

from __future__ import annotations

from qsma.utils.models import CodeLocation, CryptoHit, DetectionRule, ParsedFile

_ECC_IMPORT_QUALIFIERS = {
    "cryptography.hazmat.primitives.asymmetric.ec",
    "cryptography.hazmat.primitives.asymmetric.dsa",
    "cryptography.hazmat.primitives.asymmetric.dh",
    "cryptography.hazmat.primitives.asymmetric.x25519",
    "cryptography.hazmat.primitives.asymmetric.x448",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "Crypto.PublicKey.ECC",
    "Crypto.PublicKey.DSA",
    "Crypto.Signature.DSS",
}

_ECDH_CALL_NAMES = {"exchange"}
_ECDSA_IMPORT_KEYWORDS = {"ecdsa", "ecdh", "ec"}
_DSA_IMPORT_KEYWORDS = {"dsa"}
_DH_IMPORT_KEYWORDS = {"dh", "x25519", "x448"}


def _make_location(pf: ParsedFile, line: int) -> CodeLocation:
    return CodeLocation(file=pf.path, line_start=line, line_end=line)


def _has_ecc_import(pf: ParsedFile) -> bool:
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if any(k in qn for k in _ECDSA_IMPORT_KEYWORDS) or qn in _ECC_IMPORT_QUALIFIERS:
            return True
    return False


def _has_dsa_import(pf: ParsedFile) -> bool:
    for imp in pf.imports:
        if any(k in imp.qualified_name.lower() for k in _DSA_IMPORT_KEYWORDS):
            return True
    return False


def _has_dh_import(pf: ParsedFile) -> bool:
    for imp in pf.imports:
        if any(k in imp.qualified_name.lower() for k in _DH_IMPORT_KEYWORDS):
            return True
    return False


# ── ECC imports ────────────────────────────────────────────────────────────


def _match_ecc_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if any(k in qn for k in _ECDSA_IMPORT_KEYWORDS):
            algo = "ECDH" if "dh" in qn or "x25519" in qn or "x448" in qn else "ECDSA"
            hits.append(
                CryptoHit(
                    rule_id=f"ecc-import-{algo.lower()}",
                    algorithm_hint=algo,
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── DSA imports ────────────────────────────────────────────────────────────


def _match_dsa_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        if any(k in imp.qualified_name.lower() for k in _DSA_IMPORT_KEYWORDS):
            hits.append(
                CryptoHit(
                    rule_id="dsa-import",
                    algorithm_hint="DSA",
                    usage_type="import",
                    location=_make_location(pf, imp.line),
                    raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                )
            )
    return hits


# ── DH imports ────────────────────────────────────────────────────────────


def _match_dh_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        if any(k in imp.qualified_name.lower() for k in _DH_IMPORT_KEYWORDS):
            if "sha" not in imp.qualified_name.lower():
                hits.append(
                    CryptoHit(
                        rule_id="dh-import",
                        algorithm_hint="DH",
                        usage_type="import",
                        location=_make_location(pf, imp.line),
                        raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                    )
                )
    return hits


# ── ECDH key exchange call ─────────────────────────────────────────────────


def _match_ecdh_exchange(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    if not _has_ecc_import(pf):
        return hits
    for cs in pf.call_sites:
        if cs.function_name == "exchange":
            hits.append(
                CryptoHit(
                    rule_id="ecdh-key-exchange",
                    algorithm_hint="ECDH",
                    usage_type="key_exchange",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name},
                )
            )
    return hits


# ── ECDSA / EC key generation ──────────────────────────────────────────────


def _match_ecc_keygen(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    if not _has_ecc_import(pf):
        return hits
    for cs in pf.call_sites:
        if cs.function_name == "generate_private_key":
            # Only flag here if NOT flagged as RSA (no "rsa" import qualifier)
            has_rsa = any("rsa" in imp.qualified_name.lower() for imp in pf.imports)
            if has_rsa:
                continue
            hits.append(
                CryptoHit(
                    rule_id="ecc-key-generation",
                    algorithm_hint="ECDSA",
                    usage_type="key_generation",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": cs.function_name},
                )
            )
    return hits


ECC_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="ecc-import-ecdsa",
        algorithm_hint="ECDSA",
        usage_type="import",
        matcher_fn=_match_ecc_import,
    ),
    DetectionRule(
        rule_id="dsa-import",
        algorithm_hint="DSA",
        usage_type="import",
        matcher_fn=_match_dsa_import,
    ),
    DetectionRule(
        rule_id="dh-import",
        algorithm_hint="DH",
        usage_type="import",
        matcher_fn=_match_dh_import,
    ),
    DetectionRule(
        rule_id="ecdh-key-exchange",
        algorithm_hint="ECDH",
        usage_type="key_exchange",
        matcher_fn=_match_ecdh_exchange,
    ),
    DetectionRule(
        rule_id="ecc-key-generation",
        algorithm_hint="ECDSA",
        usage_type="key_generation",
        matcher_fn=_match_ecc_keygen,
    ),
]
