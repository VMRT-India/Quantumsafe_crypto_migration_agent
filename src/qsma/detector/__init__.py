"""
qsma.detector
=============
Public API for the Detector module.

Usage::

    from qsma.detector import detect
    hits, graph = detect(analysis_result, session_id="scan-001")
"""

from __future__ import annotations

import uuid
from pathlib import Path

from qsma.detector.graph import build_dependency_graph
from qsma.detector.runner import run_detection
from qsma.utils.models import AnalysisResult, CryptoHit, DependencyGraph


def detect(
    analysis: AnalysisResult,
    session_id: str | None = None,
    root_path: Path | None = None,
) -> tuple[list[CryptoHit], DependencyGraph]:
    """
    Run the full Detector pipeline (Phase A + Phase B) on an AnalysisResult.

    Phase A — pattern matching:
        Apply all DetectionRules from the patterns library to every ParsedFile.

    Phase B — dependency graph:
        Build the intra-codebase DependencyGraph, compute transitive dependents,
        mark has_crypto on relevant nodes, tag each CryptoHit with its
        dependency_node_id, and optionally persist to Neo4j.

    Parameters
    ----------
    analysis:
        Output of qsma.analyzer.analyse_snapshot().
    session_id:
        Stable scan session ID.  Auto-generated if not supplied.
    root_path:
        Codebase root path used for module name inference.  Optional.

    Returns
    -------
    (hits, graph)
        hits:  list[CryptoHit] — pattern-matched crypto usage sites
        graph: DependencyGraph — full in-memory dependency graph
    """
    if session_id is None:
        session_id = str(uuid.uuid4())

    # Phase A
    hits = run_detection(analysis)

    # Phase B
    graph = build_dependency_graph(analysis, hits, session_id, root_path)

    return hits, graph


__all__ = ["detect"]
