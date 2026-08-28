"""
INTENTIONALLY VULNERABLE — test fixture for qsma detector/migrator tests.
This file uses AES-128 which has reduced security against Grover's algorithm.
DO NOT USE IN PRODUCTION.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt_data(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt data with AES-128-CBC. Key strength REDUCED by quantum."""
    key = os.urandom(16)   # 128-bit key — should be 256-bit post-quantum
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return key, iv, ciphertext
