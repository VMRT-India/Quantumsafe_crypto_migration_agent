"""
INTENTIONALLY VULNERABLE — test fixture for qsma detector/migrator tests.
This file uses ECDH over SECP256R1 which is quantum-vulnerable (Shor's algorithm).
DO NOT USE IN PRODUCTION.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def perform_ecdh_exchange(peer_public_key):
    """Perform ECDH key exchange. QUANTUM-VULNERABLE."""
    private_key = generate_private_key(SECP256R1())
    shared_key = private_key.exchange(ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake",
    ).derive(shared_key)

    return derived_key, private_key.public_key()
