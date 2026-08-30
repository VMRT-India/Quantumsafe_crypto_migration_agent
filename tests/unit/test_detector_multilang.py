"""
Unit tests for the multilingual Detector rules (Java/Go/C/Rust additions to
rsa.py, ecc.py, symmetric.py, hashing.py) plus the Analyzer extraction changes
that make them possible (Java factory_calls, Go/Rust qualified call sites).

Each test parses a small real (tree-sitter-parseable) snippet with
qsma.analyzer.parser.parse_file and runs the full ALL_RULES set through
run_detection, checking the expected algorithm_hint/usage_type combination
appears among the hits — mirroring the existing Python-only tests in
test_detector.py but for the languages added in this pass.
"""

from __future__ import annotations

from pathlib import Path

from qsma.analyzer.parser import parse_file
from qsma.detector.patterns import ALL_RULES
from qsma.detector.runner import apply_rules


def hits_for(source: str, path: str, language: str):
    pf = parse_file(source, Path(path), language)
    return apply_rules(pf, ALL_RULES)


def has_hit(hits, algorithm_hint: str, usage_type: str) -> bool:
    return any(h.algorithm_hint == algorithm_hint and h.usage_type == usage_type for h in hits)


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

JAVA_RSA_SOURCE = """
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;

public class Crypto {
    public void gen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    }
}
"""

JAVA_AES_SOURCE = """
import javax.crypto.Cipher;

public class Crypto {
    public void encrypt() throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
"""

JAVA_MD5_SOURCE = """
import java.security.MessageDigest;

public class Hasher {
    public void hash() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
"""


def test_java_rsa_keygen_detected():
    hits = hits_for(JAVA_RSA_SOURCE, "Crypto.java", "java")
    assert has_hit(hits, "RSA", "key_generation")


def test_java_aes_encryption_detected():
    hits = hits_for(JAVA_AES_SOURCE, "Crypto.java", "java")
    assert has_hit(hits, "AES-128", "encryption")


def test_java_md5_hashing_detected():
    hits = hits_for(JAVA_MD5_SOURCE, "Hasher.java", "java")
    assert has_hit(hits, "MD5", "hashing")


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

GO_RSA_SOURCE = """
package main
import "crypto/rsa"
func main() {
    rsa.GenerateKey(rand.Reader, 2048)
}
"""

GO_AES_SOURCE = """
package main
import "crypto/aes"
func main() {
    aes.NewCipher(key)
}
"""

GO_SHA256_SOURCE = """
package main
import "crypto/sha256"
func main() {
    sha256.Sum256(data)
}
"""


def test_go_rsa_keygen_detected():
    hits = hits_for(GO_RSA_SOURCE, "main.go", "go")
    assert has_hit(hits, "RSA", "key_generation")


def test_go_aes_encryption_detected():
    hits = hits_for(GO_AES_SOURCE, "main.go", "go")
    assert has_hit(hits, "AES-128", "encryption")


def test_go_sha256_hashing_detected():
    hits = hits_for(GO_SHA256_SOURCE, "main.go", "go")
    assert has_hit(hits, "SHA-256", "hashing")


# ---------------------------------------------------------------------------
# C
# ---------------------------------------------------------------------------

C_RSA_SOURCE = """
#include <openssl/rsa.h>
void gen() {
    RSA *key = RSA_generate_key_ex(rsa, 2048, e, NULL);
}
"""

C_AES_SOURCE = """
#include <openssl/aes.h>
void enc() {
    AES_set_encrypt_key(key, 128, &aes_key);
}
"""

C_SHA256_SOURCE = """
#include <openssl/sha.h>
void hash() {
    SHA256_Init(&ctx);
}
"""


def test_c_rsa_keygen_detected():
    hits = hits_for(C_RSA_SOURCE, "crypto.c", "c")
    assert has_hit(hits, "RSA", "key_generation")


def test_c_aes_encryption_detected():
    hits = hits_for(C_AES_SOURCE, "crypto.c", "c")
    assert has_hit(hits, "AES-128", "encryption")


def test_c_sha256_hashing_detected():
    hits = hits_for(C_SHA256_SOURCE, "crypto.c", "c")
    assert has_hit(hits, "SHA-256", "hashing")


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

RUST_RSA_SOURCE = """
use rsa::RsaPrivateKey;
fn main() {
    let sk = RsaPrivateKey::new(&mut rng, 2048);
}
"""

RUST_AES_SOURCE = """
use aes::Aes256;
fn main() {
    let cipher = Aes256::new(&key);
}
"""

RUST_SHA256_SOURCE = """
use sha2::Sha256;
fn main() {
    let h = Sha256::new();
}
"""


def test_rust_rsa_keygen_detected():
    hits = hits_for(RUST_RSA_SOURCE, "main.rs", "rust")
    assert has_hit(hits, "RSA", "key_generation")


def test_rust_aes_encryption_detected():
    hits = hits_for(RUST_AES_SOURCE, "main.rs", "rust")
    assert has_hit(hits, "AES-256", "encryption")


def test_rust_sha256_hashing_detected():
    hits = hits_for(RUST_SHA256_SOURCE, "main.rs", "rust")
    assert has_hit(hits, "SHA-256", "hashing")
