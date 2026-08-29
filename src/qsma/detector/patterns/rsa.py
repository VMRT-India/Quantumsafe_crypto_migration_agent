"""
src/qsma/detector/patterns/rsa.py
==================================
Detection rules for RSA usage.

Covers:
- Importing RSA-related modules (cryptography.hazmat.primitives.asymmetric.rsa,
  Crypto.PublicKey.RSA, rsa)
- Calling RSA key generation functions
- Calling RSA encryption/decryption operations
- Calling RSA sign/verify operations

Each rule is a DetectionRule whose matcher_fn receives a ParsedFile and returns
a list[CryptoHit].
"""

from __future__ import annotations

from qsma.utils.models import CodeLocation, CryptoHit, DetectionRule, ParsedFile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RULE_ID_PREFIX = "rsa"

_RSA_IMPORT_MODULES = {
    "rsa",
    "cryptography",  # hazmat.primitives.asymmetric.rsa is under cryptography
    "Crypto",  # pycryptodome: Crypto.PublicKey.RSA
}

_RSA_IMPORT_QUALIFIERS = {
    "cryptography.hazmat.primitives.asymmetric.rsa",
    "cryptography.hazmat.primitives.asymmetric",
    "cryptography.hazmat.primitives.asymmetric.padding",
    "Crypto.PublicKey.RSA",
    "Crypto.Signature.pkcs1_15",
    "Crypto.Signature.pss",
}

# Import aliases / top-level names that indicate RSA context
_RSA_IMPORT_MODULE_HINTS = {
    "rsa",
    "cryptography",  # cryptography.hazmat.primitives.asymmetric.rsa
    "Crypto",  # pycryptodome Crypto.PublicKey.RSA
}

_RSA_CALL_NAMES = {
    "generate_private_key",  # cryptography
    "generate",  # Crypto.PublicKey.RSA.generate
    "importKey",  # Crypto legacy
    "import_key",  # Crypto
}

_RSA_CALL_QUALIFIED = {
    "rsa.generate_private_key",
    "RSA.generate",
    "RSA.import_key",
    "RSA.importKey",
}


def _make_location(pf: ParsedFile, line: int) -> CodeLocation:
    return CodeLocation(file=pf.path, line_start=line, line_end=line)


# ---------------------------------------------------------------------------
# Rule: RSA import detected
# ---------------------------------------------------------------------------


def _has_rsa_context(pf: ParsedFile) -> bool:
    """Return True if any import in the file indicates RSA usage."""
    for imp in pf.imports:
        qn = imp.qualified_name.lower()
        if "rsa" in qn or "asymmetric" in qn or "pkcs1" in qn or imp.module == "rsa":
            return True
        # qualified call names: rsa.generate_private_key
        if any(
            cs.function_name in _RSA_CALL_NAMES or (cs.qualified_name or "").startswith("rsa.")
            for cs in pf.call_sites
        ):
            return True
    return False


def _match_rsa_import(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for imp in pf.imports:
        if imp.module in _RSA_IMPORT_MODULES or imp.qualified_name in _RSA_IMPORT_QUALIFIERS:
            # Refine: only flag if the qualified name actually points to RSA
            qn = imp.qualified_name.lower()
            if "rsa" in qn or "asymmetric" in qn or "pkcs1" in qn or imp.module == "rsa":
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-import",
                        algorithm_hint="RSA",
                        usage_type="import",
                        location=_make_location(pf, imp.line),
                        raw_node_info={"module": imp.module, "qualified_name": imp.qualified_name},
                    )
                )
    return hits


# ---------------------------------------------------------------------------
# Rule: RSA key generation call
# ---------------------------------------------------------------------------


def _match_rsa_keygen(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    for cs in pf.call_sites:
        fn = cs.function_name
        qn = cs.qualified_name or ""
        if fn in _RSA_CALL_NAMES or qn in _RSA_CALL_QUALIFIED:
            # Disambiguate: generate_private_key is also used for EC —
            # only flag if RSA context (qualified call is "rsa.*" OR rsa import present)
            if fn == "generate_private_key":
                is_rsa_call = qn.startswith("rsa.") or "RSA" in qn
                has_rsa_import = any(
                    "rsa" in imp.qualified_name.lower()
                    or "asymmetric" in imp.qualified_name.lower()
                    or imp.module == "rsa"
                    for imp in pf.imports
                )
                if not is_rsa_call and not has_rsa_import:
                    continue
                # If asymmetric import present, require qualified name to not be
                # purely EC-oriented (no "ec" prefix)
                if has_rsa_import and not is_rsa_call:
                    # Additional guard: if ECDH.exchange is also present, skip
                    has_ec_context = any(
                        "ec" in imp.qualified_name.lower()
                        and "rsa" not in imp.qualified_name.lower()
                        for imp in pf.imports
                    )
                    if has_ec_context:
                        continue
            hits.append(
                CryptoHit(
                    rule_id=f"{_RULE_ID_PREFIX}-key-generation",
                    algorithm_hint="RSA",
                    usage_type="key_generation",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": fn, "qualified_name": qn},
                )
            )
    return hits


# ---------------------------------------------------------------------------
# Rule: RSA sign / verify
# ---------------------------------------------------------------------------


def _match_rsa_sign(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []
    has_rsa_import = any(
        "rsa" in imp.qualified_name.lower()
        or "asymmetric" in imp.qualified_name.lower()
        or imp.module == "rsa"
        for imp in pf.imports
    )
    if not has_rsa_import:
        return hits

    for cs in pf.call_sites:
        fn = cs.function_name
        if (
            fn in ("sign", "verify")
            and cs.qualified_name
            and ("pkcs1" in (cs.qualified_name.lower()) or "pss" in (cs.qualified_name.lower()))
        ):
            hits.append(
                CryptoHit(
                    rule_id=f"{_RULE_ID_PREFIX}-{'signature' if fn == 'sign' else 'verify'}",
                    algorithm_hint="RSA",
                    usage_type="signature",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": fn},
                )
            )
        elif fn in ("sign", "verify") and has_rsa_import:
            hits.append(
                CryptoHit(
                    rule_id=f"{_RULE_ID_PREFIX}-{'signature' if fn == 'sign' else 'verify'}",
                    algorithm_hint="RSA",
                    usage_type="signature",
                    location=_make_location(pf, cs.line),
                    raw_node_info={"function": fn},
                )
            )
    return hits


# ---------------------------------------------------------------------------
# Exported rules
# ---------------------------------------------------------------------------

RSA_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id=f"{_RULE_ID_PREFIX}-import",
        algorithm_hint="RSA",
        usage_type="import",
        matcher_fn=_match_rsa_import,
    ),
    DetectionRule(
        rule_id=f"{_RULE_ID_PREFIX}-key-generation",
        algorithm_hint="RSA",
        usage_type="key_generation",
        matcher_fn=_match_rsa_keygen,
    ),
    DetectionRule(
        rule_id=f"{_RULE_ID_PREFIX}-signature",
        algorithm_hint="RSA",
        usage_type="signature",
        matcher_fn=_match_rsa_sign,
    ),
]
