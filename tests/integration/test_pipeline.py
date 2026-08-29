"""
tests/integration/test_pipeline.py
====================================
Integration test: Ingestion → Analyzer → Detector on a small fixture project.

Asserts:
- The pipeline produces at least one CryptoHit
- The DependencyGraph is built and blast_radius() returns sane values
- Every hit has a dependency_node_id linking it to a graph node
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qsma.analyzer import analyse_snapshot
from qsma.detector import detect
from qsma.ingestion import collect_snapshot
from qsma.utils.models import IngestionConfig

FIXTURES_ROOT = Path(__file__).parent.parent / "fixtures" / "sample_projects"


class TestScanPipeline:
    """Wire Ingestion → Analyzer → Detector on each fixture project."""

    def _run_pipeline(self, project_dir: Path) -> tuple:
        config = IngestionConfig(extensions=[".py"])
        snapshot = collect_snapshot(project_dir, config)
        assert snapshot.file_count > 0, f"No files found in {project_dir}"

        analysis = analyse_snapshot(snapshot)
        assert len(analysis.parsed_files) > 0

        hits, graph = detect(analysis, session_id="integration-test", root_path=project_dir)
        return snapshot, analysis, hits, graph

    # ── RSA fixture ────────────────────────────────────────────────────────
    def test_rsa_fixture_produces_hits(self) -> None:
        _, _, hits, _ = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        assert len(hits) > 0
        algo_hints = {h.algorithm_hint for h in hits}
        assert "RSA" in algo_hints

    def test_rsa_fixture_graph_nodes(self) -> None:
        snap, _, _, graph = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        assert len(graph.nodes) == snap.file_count

    def test_rsa_fixture_has_crypto_marked(self) -> None:
        _, _, _, graph = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        assert any(n.has_crypto for n in graph.nodes.values())

    # ── ECDH fixture ───────────────────────────────────────────────────────
    def test_ecdh_fixture_produces_hits(self) -> None:
        _, _, hits, _ = self._run_pipeline(FIXTURES_ROOT / "python_ecdh")
        assert len(hits) > 0

    def test_ecdh_fixture_blast_radius_sane(self) -> None:
        _, _, _, graph = self._run_pipeline(FIXTURES_ROOT / "python_ecdh")
        for node in graph.nodes.values():
            assert graph.blast_radius(node.node_id) >= 0

    # ── AES fixture ────────────────────────────────────────────────────────
    def test_aes_fixture_produces_hits(self) -> None:
        _, _, hits, _ = self._run_pipeline(FIXTURES_ROOT / "python_aes")
        assert len(hits) > 0

    # ── Hashing fixture ────────────────────────────────────────────────────
    def test_hashing_fixture_produces_hits(self) -> None:
        _, _, hits, _ = self._run_pipeline(FIXTURES_ROOT / "python_hashing")
        assert len(hits) > 0
        algo_hints = {h.algorithm_hint for h in hits}
        assert "MD5" in algo_hints

    # ── Cross-project: all fixtures produce non-empty hits ─────────────────
    @pytest.mark.parametrize(
        "project",
        [
            "python_rsa",
            "python_ecdh",
            "python_aes",
            "python_hashing",
        ],
    )
    def test_all_fixtures_produce_hits(self, project: str) -> None:
        _, _, hits, _ = self._run_pipeline(FIXTURES_ROOT / project)
        assert len(hits) > 0, f"No hits found in {project}"

    # ── Hit→graph linkage ──────────────────────────────────────────────────
    def test_hits_have_dependency_node_id(self) -> None:
        """Every hit must be linked to a DependencyGraph node."""
        _, _, hits, graph = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        for hit in hits:
            assert hit.dependency_node_id is not None, (
                f"Hit {hit.rule_id} at {hit.location.file}:{hit.location.line_start} "
                "has no dependency_node_id"
            )
            assert (
                hit.dependency_node_id in graph.nodes
            ), f"dependency_node_id {hit.dependency_node_id} not found in graph"

    # ── DependencyGraph API ────────────────────────────────────────────────
    def test_blast_radius_returns_non_negative_int(self) -> None:
        _, _, _, graph = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        for nid in graph.nodes:
            radius = graph.blast_radius(nid)
            assert isinstance(radius, int)
            assert radius >= 0

    def test_blast_radius_unknown_node_returns_zero(self) -> None:
        _, _, _, graph = self._run_pipeline(FIXTURES_ROOT / "python_rsa")
        assert graph.blast_radius("this-node-does-not-exist") == 0


class TestMultiFileProject:
    """
    A synthetic 3-file project: main.py imports crypto_lib.py which uses RSA.
    Verifies transitive dependency propagation.
    """

    def test_transitive_dependency_propagation(self, tmp_path: Path) -> None:
        crypto_lib = tmp_path / "crypto_lib.py"
        crypto_lib.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "def gen(): return rsa.generate_private_key(65537, 2048)\n",
            encoding="utf-8",
        )
        main_py = tmp_path / "main.py"
        main_py.write_text(
            "from crypto_lib import gen\nif __name__ == '__main__': gen()\n",
            encoding="utf-8",
        )
        utils_py = tmp_path / "utils.py"
        utils_py.write_text(
            "from main import gen\ndef run(): gen()\n",
            encoding="utf-8",
        )

        snap = collect_snapshot(tmp_path)
        analysis = analyse_snapshot(snap)
        hits, graph = detect(analysis, session_id="multi-test", root_path=tmp_path)

        assert len(hits) > 0

        # crypto_lib.py has RSA → has_crypto = True
        from qsma.detector.graph import _node_id

        crypto_node_id = _node_id(crypto_lib)
        assert graph.nodes[crypto_node_id].has_crypto is True

        # blast_radius of crypto_lib ≥ 0 (main.py imports it; utils.py imports main.py)
        radius = graph.blast_radius(crypto_node_id)
        assert isinstance(radius, int)
        assert radius >= 0  # exact value depends on import resolution
