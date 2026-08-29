"""
INTENTIONALLY VULNERABLE — test fixture for qsma detector tests.
This file uses AES-128 in ECB mode which is both key-size-weak and mode-insecure.
DO NOT USE IN PRODUCTION.
"""

from Crypto.Cipher import AES

SECRET_KEY = b"mysecretkey12345"  # 16 bytes = 128-bit key  (QUANTUM-WEAK)


def encrypt_ecb(plaintext: bytes) -> bytes:
    """Encrypt with AES-128-ECB. KEY SIZE and MODE are both problematic."""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    # Pad plaintext to 16-byte blocks
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


def decrypt_ecb(ciphertext: bytes) -> bytes:
    """Decrypt AES-128-ECB ciphertext."""
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]
