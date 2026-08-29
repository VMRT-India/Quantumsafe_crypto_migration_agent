"""
tests/unit/test_analyzer.py
Unit tests for the Analyzer module (T-03).
"""

from __future__ import annotations

from pathlib import Path

from qsma.analyzer.crypto_imports import is_crypto_import
from qsma.analyzer.parser import analyse_snapshot, parse_file
from qsma.utils.models import CodebaseSnapshot, SourceFile

# ---------------------------------------------------------------------------
# Crypto import allowlist
# ---------------------------------------------------------------------------


class TestCryptoImportAllowlist:
    def test_cryptography_is_crypto(self) -> None:
        assert is_crypto_import("cryptography", "python") is True

    def test_hashlib_is_crypto(self) -> None:
        assert is_crypto_import("hashlib", "python") is True

    def test_hmac_is_crypto(self) -> None:
        assert is_crypto_import("hmac", "python") is True

    def test_ssl_is_crypto(self) -> None:
        assert is_crypto_import("ssl", "python") is True

    def test_paramiko_is_crypto(self) -> None:
        assert is_crypto_import("paramiko", "python") is True

    def test_pycryptodome_top_level(self) -> None:
        assert is_crypto_import("Crypto", "python") is True

    def test_os_is_not_crypto(self) -> None:
        assert is_crypto_import("os", "python") is False

    def test_sys_is_not_crypto(self) -> None:
        assert is_crypto_import("sys", "python") is False

    def test_java_javax_crypto(self) -> None:
        assert is_crypto_import("javax.crypto", "java") is True

    def test_go_crypto_rsa(self) -> None:
        assert is_crypto_import("crypto/rsa", "go") is True

    def test_go_crypto_umbrella(self) -> None:
        assert is_crypto_import("crypto", "go") is True

    def test_rust_ring(self) -> None:
        assert is_crypto_import("ring", "rust") is True

    def test_unknown_language(self) -> None:
        assert is_crypto_import("something", "cobol") is False


# ---------------------------------------------------------------------------
# parse_file — Python
# ---------------------------------------------------------------------------

RSA_SOURCE = """\
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
"""

ECDH_SOURCE = """\
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1
)

def do_key_exchange():
    private_key = generate_private_key(SECP256R1())
    peer_public_key = private_key.public_key()
    shared_key = private_key.exchange(ECDH(), peer_public_key)
    return shared_key
"""

HASHLIB_SOURCE = """\
import hashlib

def checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
"""


class TestParseFilePython:
    def test_imports_extracted(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        modules = {imp.module for imp in pf.imports}
        assert "cryptography" in modules

    def test_crypto_imports_flagged(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        crypto_mods = [imp for imp in pf.imports if imp.is_crypto]
        assert len(crypto_mods) > 0

    def test_function_defs_extracted(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        assert "generate_key" in pf.function_defs
        assert "sign" in pf.function_defs

    def test_call_sites_extracted(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        fn_names = {cs.function_name for cs in pf.call_sites}
        assert "generate_private_key" in fn_names

    def test_ts_tree_present(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        assert pf.ts_tree is not None

    def test_cst_tree_present(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        assert pf.cst_tree is not None

    def test_ecdh_import_flagged(self) -> None:
        pf = parse_file(ECDH_SOURCE, Path("key_ex.py"), "python")
        crypto_imports = [i for i in pf.imports if i.is_crypto]
        assert len(crypto_imports) > 0

    def test_hashlib_md5_call(self) -> None:
        pf = parse_file(HASHLIB_SOURCE, Path("hash.py"), "python")
        fn_names = {cs.function_name for cs in pf.call_sites}
        assert "md5" in fn_names

    def test_intra_file_calls_built(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        # intra_file_calls maps callee → [caller]
        assert isinstance(pf.intra_file_calls, dict)

    def test_language_is_python(self) -> None:
        pf = parse_file(RSA_SOURCE, Path("crypto.py"), "python")
        assert pf.language == "python"


# ---------------------------------------------------------------------------
# analyse_snapshot
# ---------------------------------------------------------------------------


class TestAnalyseSnapshot:
    def _make_snapshot(self, files: dict[str, str], tmp_path: Path) -> CodebaseSnapshot:
        source_files = []
        for name, content in files.items():
            p = tmp_path / name
            p.write_text(content, encoding="utf-8")
            source_files.append(
                SourceFile(path=p, content=content, language="python", size_bytes=len(content))
            )
        return CodebaseSnapshot(
            root_path=tmp_path, files=source_files, file_count=len(source_files)
        )

    def test_analyse_rsa_snapshot(self, tmp_path: Path) -> None:
        snap = self._make_snapshot({"crypto.py": RSA_SOURCE}, tmp_path)
        result = analyse_snapshot(snap)
        assert len(result.parsed_files) == 1
        assert result.parsed_files[0].language == "python"

    def test_import_index_populated(self, tmp_path: Path) -> None:
        snap = self._make_snapshot({"crypto.py": RSA_SOURCE}, tmp_path)
        result = analyse_snapshot(snap)
        assert "cryptography" in result.import_index

    def test_multi_file_snapshot(self, tmp_path: Path) -> None:
        snap = self._make_snapshot(
            {"a.py": RSA_SOURCE, "b.py": ECDH_SOURCE},
            tmp_path,
        )
        result = analyse_snapshot(snap)
        assert len(result.parsed_files) == 2

    def test_fixture_rsa_project(self) -> None:
        """Integration smoke-test: parse the real RSA fixture."""
        fixture = Path(__file__).parent.parent / "fixtures" / "sample_projects" / "python_rsa"
        from qsma.ingestion import collect_snapshot

        snap = collect_snapshot(fixture)
        result = analyse_snapshot(snap)
        assert len(result.parsed_files) >= 1
        # Should detect cryptography as a crypto import
        assert "cryptography" in result.import_index

    def test_empty_snapshot(self, tmp_path: Path) -> None:
        snap = CodebaseSnapshot(root_path=tmp_path, files=[], file_count=0)
        result = analyse_snapshot(snap)
        assert result.parsed_files == []
        assert result.import_index == {}
