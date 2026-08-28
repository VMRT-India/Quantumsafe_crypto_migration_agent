"""
Shared pytest fixtures for the Quantum-Safe Crypto Migration Agent test suite.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


@pytest.fixture()
def sample_rsa_code() -> str:
    """Minimal Python snippet using RSA (quantum-vulnerable)."""
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes

        def generate_key():
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            return private_key

        def sign(private_key, message: bytes) -> bytes:
            return private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
    """)


@pytest.fixture()
def sample_ecdh_code() -> str:
    """Minimal Python snippet using ECDH key exchange (quantum-vulnerable)."""
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH, generate_private_key, SECP256R1
        )

        def do_key_exchange():
            private_key = generate_private_key(SECP256R1())
            peer_public_key = private_key.public_key()  # simplified
            shared_key = private_key.exchange(ECDH(), peer_public_key)
            return shared_key
    """)


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal temporary project structure for integration tests."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    return tmp_path
