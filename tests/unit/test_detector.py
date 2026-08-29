"""
tests/unit/test_detector.py
Unit tests for the Detector module (T-04 / T-05).
"""

from __future__ import annotations

from pathlib import Path

from qsma.analyzer.parser import parse_file
from qsma.detector.graph import _compute_transitive, _node_id, build_dependency_graph
from qsma.detector.patterns import ALL_RULES
from qsma.detector.patterns.ecc import _match_ecc_keygen, _match_ecdh_exchange
from qsma.detector.patterns.hashing import _match_md5_call
from qsma.detector.patterns.rsa import RSA_RULES, _match_rsa_import, _match_rsa_keygen
from qsma.detector.patterns.symmetric import _match_aes_import
from qsma.detector.runner import apply_rules, run_detection
from qsma.utils.models import AnalysisResult, SourceFile

# ---------------------------------------------------------------------------
# Fixtures
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
"""

ECDH_SOURCE = """\
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1
)

def do_key_exchange():
    private_key = generate_private_key(SECP256R1())
    shared_key = private_key.exchange(ECDH(), None)
    return shared_key
"""

HASHLIB_SOURCE = """\
import hashlib

def checksum(data):
    return hashlib.md5(data).hexdigest()
"""

AES_SOURCE = """\
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(plaintext):
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher
"""


def _pf(source: str, name: str = "test.py") -> ParsedFile:  # noqa: F821
    return parse_file(source, Path(name), "python")


# ---------------------------------------------------------------------------
# RSA rules
# ---------------------------------------------------------------------------


class TestRsaRules:
    def test_import_rule_fires_on_rsa_import(self) -> None:
        pf = _pf(RSA_SOURCE, "crypto.py")
        hits = _match_rsa_import(pf)
        assert len(hits) > 0
        assert all(h.algorithm_hint == "RSA" for h in hits)
        assert all(h.usage_type == "import" for h in hits)

    def test_import_rule_no_false_positive(self) -> None:
        pf = _pf("import os\nimport sys\n", "plain.py")
        hits = _match_rsa_import(pf)
        assert hits == []

    def test_keygen_rule_fires(self) -> None:
        pf = _pf(RSA_SOURCE, "crypto.py")
        hits = _match_rsa_keygen(pf)
        assert len(hits) > 0
        assert all(h.rule_id == "rsa-key-generation" for h in hits)

    def test_all_rsa_rules_combined(self) -> None:
        pf = _pf(RSA_SOURCE, "crypto.py")
        hits = apply_rules(pf, RSA_RULES)
        assert len(hits) > 0

    def test_rsa_rule_ids_are_unique(self) -> None:
        rule_ids = [r.rule_id for r in RSA_RULES]
        assert len(rule_ids) == len(set(rule_ids))


# ---------------------------------------------------------------------------
# ECC rules
# ---------------------------------------------------------------------------


class TestEccRules:
    def test_ecc_import_fires(self) -> None:
        pf = _pf(ECDH_SOURCE, "kex.py")
        hits = _match_ecdh_exchange(pf)
        assert len(hits) > 0
        assert all(h.algorithm_hint == "ECDH" for h in hits)

    def test_ecc_keygen_fires(self) -> None:
        pf = _pf(ECDH_SOURCE, "kex.py")
        hits = _match_ecc_keygen(pf)
        assert len(hits) > 0

    def test_ecc_keygen_no_false_positive_on_rsa(self) -> None:
        """generate_private_key with RSA context should not be flagged as ECC."""
        pf = _pf(RSA_SOURCE, "rsa.py")
        hits = _match_ecc_keygen(pf)
        assert hits == []


# ---------------------------------------------------------------------------
# Hashing rules
# ---------------------------------------------------------------------------


class TestHashingRules:
    def test_md5_call_detected(self) -> None:
        pf = _pf(HASHLIB_SOURCE, "hash.py")
        hits = _match_md5_call(pf)
        assert len(hits) > 0
        assert all(h.algorithm_hint == "MD5" for h in hits)

    def test_sha1_not_detected_when_absent(self) -> None:
        pf = _pf(HASHLIB_SOURCE, "hash.py")
        from qsma.detector.patterns.hashing import _match_sha1_call

        hits = _match_sha1_call(pf)
        assert hits == []


# ---------------------------------------------------------------------------
# Symmetric rules
# ---------------------------------------------------------------------------


class TestSymmetricRules:
    def test_aes_import_fires(self) -> None:
        pf = _pf(AES_SOURCE, "enc.py")
        hits = _match_aes_import(pf)
        assert len(hits) > 0
        assert all(h.algorithm_hint == "AES-128" for h in hits)

    def test_des_not_detected_in_aes_file(self) -> None:
        pf = _pf(AES_SOURCE, "enc.py")
        from qsma.detector.patterns.symmetric import _match_des_import

        hits = _match_des_import(pf)
        assert hits == []


# ---------------------------------------------------------------------------
# run_detection — all rules combined
# ---------------------------------------------------------------------------


class TestRunDetection:
    def _make_analysis(self, sources: dict[str, str], tmp_path: Path) -> AnalysisResult:
        parsed = [
            parse_file(content, tmp_path / name, "python") for name, content in sources.items()
        ]
        return AnalysisResult(parsed_files=parsed, import_index={})

    def test_rsa_file_produces_hits(self, tmp_path: Path) -> None:
        analysis = self._make_analysis({"crypto.py": RSA_SOURCE}, tmp_path)
        hits = run_detection(analysis)
        assert len(hits) > 0
        algo_hints = {h.algorithm_hint for h in hits}
        assert "RSA" in algo_hints

    def test_hits_sorted_deterministically(self, tmp_path: Path) -> None:
        analysis = self._make_analysis({"a.py": RSA_SOURCE, "b.py": ECDH_SOURCE}, tmp_path)
        hits1 = run_detection(analysis)
        hits2 = run_detection(analysis)
        assert [h.rule_id for h in hits1] == [h.rule_id for h in hits2]

    def test_no_hits_on_clean_file(self, tmp_path: Path) -> None:
        clean = "x = 1\nprint(x)\n"
        analysis = self._make_analysis({"clean.py": clean}, tmp_path)
        hits = run_detection(analysis)
        assert hits == []

    def test_deduplication(self, tmp_path: Path) -> None:
        """Running detection twice on the same ParsedFile should not create duplicates."""
        analysis = self._make_analysis({"c.py": RSA_SOURCE}, tmp_path)
        hits = run_detection(analysis)
        keys = [(str(h.location.file), h.location.line_start, h.rule_id) for h in hits]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Dependency graph builder
# ---------------------------------------------------------------------------


class TestDependencyGraph:
    def _build(self, sources: dict[str, str], tmp_path: Path) -> tuple[AnalysisResult, list]:
        parsed = []
        source_files = []
        for name, content in sources.items():
            p = tmp_path / name
            p.write_text(content, encoding="utf-8")
            pf = parse_file(content, p, "python")
            parsed.append(pf)
            source_files.append(SourceFile(path=p, content=content, language="python"))

        analysis = AnalysisResult(parsed_files=parsed, import_index={})
        hits = run_detection(analysis)
        return analysis, hits

    def test_graph_has_one_node_per_file(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"a.py": RSA_SOURCE, "b.py": ECDH_SOURCE}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "test-session")
        assert len(graph.nodes) == 2

    def test_has_crypto_marked(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"crypto.py": RSA_SOURCE}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "test-session")
        assert any(n.has_crypto for n in graph.nodes.values())

    def test_clean_file_has_no_crypto(self, tmp_path: Path) -> None:
        clean = "x = 1\n"
        analysis, hits = self._build({"clean.py": clean}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "test-session")
        assert all(not n.has_crypto for n in graph.nodes.values())

    def test_blast_radius_zero_for_isolated_node(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"solo.py": RSA_SOURCE}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "test-session")
        node = list(graph.nodes.values())[0]
        assert graph.blast_radius(node.node_id) == 0

    def test_blast_radius_with_dependents(self, tmp_path: Path) -> None:
        """
        a.py imports b.py, so b's blast_radius should be at least 1.
        We use a direct intra-codebase import (module name matches file stem).
        """
        b_source = "def helper(): pass\n"
        a_source = "from b import helper\n\nhelper()\n"
        (tmp_path / "b.py").write_text(b_source, encoding="utf-8")
        (tmp_path / "a.py").write_text(a_source, encoding="utf-8")

        b_pf = parse_file(b_source, tmp_path / "b.py", "python")
        a_pf = parse_file(a_source, tmp_path / "a.py", "python")
        analysis = AnalysisResult(parsed_files=[a_pf, b_pf], import_index={})
        hits = run_detection(analysis)
        graph = build_dependency_graph(analysis, hits, "test-session", root_path=tmp_path)

        b_id = _node_id(tmp_path / "b.py")
        assert graph.blast_radius(b_id) >= 1

    def test_session_id_stored(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"f.py": "x=1\n"}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "my-session-123")
        assert graph.session_id == "my-session-123"

    def test_dependency_node_id_on_hit(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"crypto.py": RSA_SOURCE}, tmp_path)
        build_dependency_graph(analysis, hits, "s")
        crypto_hits = [h for h in hits if h.dependency_node_id is not None]
        assert len(crypto_hits) > 0

    def test_compute_transitive_empty(self) -> None:
        result = _compute_transitive("a", {})
        assert result == []

    def test_compute_transitive_chain(self) -> None:
        # a depends on b, b depends on c → transitive deps of c = {a, b}
        reverse = {"c": ["b"], "b": ["a"]}
        result = _compute_transitive("c", reverse)
        assert "a" in result
        assert "b" in result

    def test_blast_radius_unknown_node(self, tmp_path: Path) -> None:
        analysis, hits = self._build({"x.py": "y=1\n"}, tmp_path)
        graph = build_dependency_graph(analysis, hits, "s")
        assert graph.blast_radius("nonexistent-node") == 0


# ---------------------------------------------------------------------------
# ALL_RULES completeness
# ---------------------------------------------------------------------------


class TestAllRules:
    def test_all_rules_non_empty(self) -> None:
        assert len(ALL_RULES) > 0

    def test_no_duplicate_rule_ids(self) -> None:
        rule_ids = [r.rule_id for r in ALL_RULES]
        assert len(rule_ids) == len(set(rule_ids))

    def test_all_rules_have_matcher_fn(self) -> None:
        for rule in ALL_RULES:
            assert callable(rule.matcher_fn), f"Rule {rule.rule_id} has no callable matcher_fn"
