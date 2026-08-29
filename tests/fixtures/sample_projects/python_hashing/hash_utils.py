"""
INTENTIONALLY VULNERABLE — test fixture for qsma detector tests.
This file uses MD5 and SHA-1 which are broken hash algorithms.
DO NOT USE IN PRODUCTION.
"""

import hashlib
import hmac


def hash_password_md5(password: str) -> str:
    """Hash a password with MD5. CRYPTOGRAPHICALLY BROKEN."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_message_sha1(message: bytes) -> str:
    """Hash a message with SHA-1. CRYPTOGRAPHICALLY WEAK."""
    return hashlib.sha1(message).hexdigest()


def compute_hmac_md5(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-MD5. Broken due to MD5 underlying hash."""
    return hmac.new(key, message, hashlib.md5).digest()
