"""
INTENTIONALLY VULNERABLE — test fixture for qsma detector/migrator tests.
This file uses RSA-2048 which is quantum-vulnerable (Shor's algorithm).
DO NOT USE IN PRODUCTION.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair():
    """Generate an RSA-2048 private key. QUANTUM-VULNERABLE."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def sign_message(private_key, message: bytes) -> bytes:
    """Sign a message with RSA-PKCS1v15. QUANTUM-VULNERABLE."""
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """Verify an RSA signature. QUANTUM-VULNERABLE."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
