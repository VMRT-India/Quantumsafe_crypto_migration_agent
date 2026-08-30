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
# Rule: RSA usage in Java / Go / C / Rust
# ---------------------------------------------------------------------------
# Unlike Python, these languages' crypto APIs mostly disambiguate the
# algorithm by function/type name alone (RSA_generate_key_ex, rsa.GenerateKey,
# RsaPrivateKey::new) rather than by a runtime string argument — the one
# exception is Java's JCA factory pattern (Cipher.getInstance("RSA/...")),
# which the Analyzer captures separately as a "factory_calls" CallSite with
# qualified_name="<Receiver>.getInstance" and the algorithm string in
# cs.arguments (see qsma.analyzer.parser._extract_generic).

_JAVA_RSA_RECEIVERS = {"KeyPairGenerator", "Cipher", "Signature"}
_GO_RSA_QUALIFIED = {
    "rsa.GenerateKey": "key_generation",
    "rsa.EncryptOAEP": "encryption",
    "rsa.EncryptPKCS1v15": "encryption",
    "rsa.DecryptOAEP": "encryption",
    "rsa.DecryptPKCS1v15": "encryption",
    "rsa.SignPKCS1v15": "signature",
    "rsa.SignPSS": "signature",
    "rsa.VerifyPKCS1v15": "signature",
}
_C_RSA_FUNCS = {
    "RSA_generate_key": "key_generation",
    "RSA_generate_key_ex": "key_generation",
    "RSA_public_encrypt": "encryption",
    "RSA_private_decrypt": "encryption",
    "RSA_sign": "signature",
    "RSA_verify": "signature",
}
_RUST_RSA_RECEIVERS = {"RsaPrivateKey", "RsaPublicKey"}


def _match_rsa_multilang(pf: ParsedFile) -> list[CryptoHit]:
    hits: list[CryptoHit] = []

    if pf.language == "java":
        for cs in pf.call_sites:
            recv = (cs.qualified_name or "").split(".")[0]
            if (
                cs.function_name == "getInstance"
                and recv in _JAVA_RSA_RECEIVERS
                and cs.arguments
                and "RSA" in cs.arguments[0].upper()
            ):
                usage_type = "key_generation" if recv == "KeyPairGenerator" else (
                    "signature" if recv == "Signature" else "encryption"
                )
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-java-{usage_type}",
                        algorithm_hint="RSA",
                        usage_type=usage_type,
                        location=_make_location(pf, cs.line),
                        raw_node_info={"qualified_name": cs.qualified_name, "arg": cs.arguments[0]},
                    )
                )

    elif pf.language == "go":
        for imp in pf.imports:
            if imp.qualified_name in ("crypto/rsa", "rsa"):
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-import",
                        algorithm_hint="RSA",
                        usage_type="import",
                        location=_make_location(pf, imp.line),
                        raw_node_info={"module": imp.module},
                    )
                )
        for cs in pf.call_sites:
            go_usage_type = _GO_RSA_QUALIFIED.get(cs.qualified_name or "")
            if go_usage_type:
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-go-{go_usage_type}",
                        algorithm_hint="RSA",
                        usage_type=go_usage_type,
                        location=_make_location(pf, cs.line),
                        raw_node_info={"qualified_name": cs.qualified_name},
                    )
                )

    elif pf.language == "c":
        for imp in pf.imports:
            if "rsa" in imp.qualified_name.lower():
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-import",
                        algorithm_hint="RSA",
                        usage_type="import",
                        location=_make_location(pf, imp.line),
                        raw_node_info={"module": imp.module},
                    )
                )
        for cs in pf.call_sites:
            c_usage_type = _C_RSA_FUNCS.get(cs.function_name)
            if c_usage_type:
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-c-{c_usage_type}",
                        algorithm_hint="RSA",
                        usage_type=c_usage_type,
                        location=_make_location(pf, cs.line),
                        raw_node_info={"function": cs.function_name},
                    )
                )

    elif pf.language == "rust":
        for imp in pf.imports:
            if "rsa" in imp.qualified_name.lower():
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-import",
                        algorithm_hint="RSA",
                        usage_type="import",
                        location=_make_location(pf, imp.line),
                        raw_node_info={"module": imp.module},
                    )
                )
        for cs in pf.call_sites:
            recv = (cs.qualified_name or "").split(".")[0]
            if cs.function_name == "new" and recv in _RUST_RSA_RECEIVERS:
                hits.append(
                    CryptoHit(
                        rule_id=f"{_RULE_ID_PREFIX}-rust-key-generation",
                        algorithm_hint="RSA",
                        usage_type="key_generation",
                        location=_make_location(pf, cs.line),
                        raw_node_info={"qualified_name": cs.qualified_name},
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
    DetectionRule(
        rule_id=f"{_RULE_ID_PREFIX}-multilang",
        algorithm_hint="RSA",
        usage_type="key_generation",
        matcher_fn=_match_rsa_multilang,
    ),
]
