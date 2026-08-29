"""
qsma.analyzer.crypto_imports
=============================
Per-language allowlists of cryptographic module names used by the Analyzer
to flag which imports are cryptography-related.

To add a new language, add an entry to CRYPTO_IMPORTS keyed by the language
string returned by the Ingestion layer.

Sources:
- Python: cryptography, pycryptodome, hashlib, hmac, ssl, paramiko
- Java:   javax.crypto, java.security, org.bouncycastle, com.nimbusds
- Go:     crypto/*, golang.org/x/crypto
- C:      openssl, libsodium (detected via include strings)
- Rust:   ring, rustls, rsa, ed25519-dalek, p256, sha2, aes, hmac
"""

from __future__ import annotations

CRYPTO_IMPORTS: dict[str, set[str]] = {
    "python": {
        # PEP-517 package names ↔ top-level import names
        "cryptography",
        "Crypto",  # pycryptodome — top-level import is "Crypto"
        "hashlib",
        "hmac",
        "ssl",
        "paramiko",
        "rsa",  # pure-python rsa package
        "nacl",  # PyNaCl
        "OpenSSL",  # pyOpenSSL
    },
    "java": {
        "javax.crypto",
        "java.security",
        "java.security.spec",
        "javax.net.ssl",
        "org.bouncycastle",
        "com.nimbusds",
        "sun.security",
    },
    "go": {
        "crypto",  # crypto/* stdlib umbrella
        "crypto/rsa",
        "crypto/ecdsa",
        "crypto/dsa",
        "crypto/elliptic",
        "crypto/aes",
        "crypto/des",
        "crypto/md5",
        "crypto/sha1",
        "crypto/sha256",
        "crypto/sha512",
        "crypto/hmac",
        "crypto/tls",
        "crypto/x509",
        "golang.org/x/crypto",
        "github.com/golang-jwt/jwt",
    },
    "c": {
        # C "imports" are #include paths — top-level header names
        "openssl/rsa.h",
        "openssl/evp.h",
        "openssl/ssl.h",
        "openssl/ec.h",
        "openssl/aes.h",
        "openssl/des.h",
        "openssl/md5.h",
        "openssl/sha.h",
        "openssl/hmac.h",
        "sodium.h",
        "gcrypt.h",
    },
    "rust": {
        "ring",
        "rustls",
        "rsa",
        "ed25519_dalek",
        "p256",
        "k256",
        "sha2",
        "sha1",
        "md5",
        "aes",
        "des",
        "hmac",
        "pbkdf2",
        "scrypt",
        "argon2",
        "openssl",
    },
}


def is_crypto_import(module: str, language: str) -> bool:
    """Return True if the given module name is a known crypto import for the language."""
    allowlist = CRYPTO_IMPORTS.get(language, set())
    # Exact match first
    if module in allowlist:
        return True
    # Prefix match: "crypto/rsa" → "crypto" covers the full stdlib tree in Go
    for entry in allowlist:
        if module == entry or module.startswith(entry + "/") or module.startswith(entry + "."):
            return True
    return False
