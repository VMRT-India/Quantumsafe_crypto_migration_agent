"""
qsma.detector.graph
====================
Phase B: Build the intra-codebase dependency graph from Analyzer output.

Steps
-----
1. Create one DependencyNode per ParsedFile (keyed by absolute file path).
2. For each file's import list, resolve imports to other nodes in the same
   codebase and add directed edges (importer → importee).
3. Compute direct_dependents and transitive_dependents for each node
   (BFS from every node in the reverse-edge graph).
4. Mark has_crypto = True on any node that has ≥1 CryptoHit.
5. Return a DependencyGraph with the in-memory nodes + edges.

Neo4j persistence is an optional side-effect:
If NEO4J_URI is set in the environment, the graph is persisted using the
Neo4j Python driver.  If not, the function completes cleanly with no error.
"""

from __future__ import annotations

import logging
import os
from collections import deque
from pathlib import Path

from qsma.utils.models import (
    AnalysisResult,
    CryptoHit,
    DependencyGraph,
    DependencyNode,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_id(path: Path) -> str:
    """Stable node ID from an absolute, normalised file path."""
    return str(path.resolve())


def _module_name_from_path(path: Path, root: Path | None = None) -> str:
    """
    Convert a file path to a Python dotted module name, relative to root if given.
    Falls back to the stem for non-Python languages.
    """
    if root is not None:
        try:
            rel = path.relative_to(root)
            parts = list(rel.parts)
            if parts and parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            # Drop __init__
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            return ".".join(parts) if parts else path.stem
        except ValueError:
            pass
    return path.stem


def _compute_transitive(
    node_id: str,
    reverse_edges: dict[str, list[str]],
) -> list[str]:
    """
    BFS from node_id in the *reverse* edge map (dependent → what it depends on)
    to find all modules that transitively depend on node_id.
    """
    visited: set[str] = set()
    queue: deque[str] = deque([node_id])
    while queue:
        current = queue.popleft()
        for dependent in reverse_edges.get(current, []):
            if dependent not in visited and dependent != node_id:
                visited.add(dependent)
                queue.append(dependent)
    return sorted(visited)


# ---------------------------------------------------------------------------
# Main graph builder
# ---------------------------------------------------------------------------


def build_dependency_graph(
    analysis: AnalysisResult,
    hits: list[CryptoHit],
    session_id: str,
    root_path: Path | None = None,
) -> DependencyGraph:
    """
    Build the full in-memory DependencyGraph and (optionally) persist to Neo4j.

    Parameters
    ----------
    analysis:
        Analyzer output containing all ParsedFile objects.
    hits:
        The CryptoHits from Phase A — used to set has_crypto and tag each hit
        with its dependency_node_id.
    session_id:
        Stable scan ID; used as a key in Neo4j for session isolation.
    root_path:
        Codebase root; used for module name inference.  Optional.

    Returns
    -------
    DependencyGraph
        In-memory graph with transitive_dependents computed for every node.
        The `hits` list is mutated in place: dependency_node_id is set on
        each hit that maps to a known node.
    """
    # ── Step 1: create nodes ───────────────────────────────────────────────
    nodes: dict[str, DependencyNode] = {}
    for pf in analysis.parsed_files:
        nid = _node_id(pf.path)
        nodes[nid] = DependencyNode(
            node_id=nid,
            module_name=_module_name_from_path(pf.path, root_path),
            file=pf.path,
            language=pf.language,
        )

    # ── Step 2: resolve imports → edges ───────────────────────────────────
    # Build a lookup: module_name → node_id (for intra-codebase resolution)
    module_to_node: dict[str, str] = {node.module_name: nid for nid, node in nodes.items()}
    # Also index by file stem for simple cases
    stem_to_node: dict[str, str] = {Path(node.file).stem: nid for nid, node in nodes.items()}

    # edges: importer_node_id → list of importee_node_ids (direct deps)
    edges: dict[str, list[str]] = {nid: [] for nid in nodes}

    for pf in analysis.parsed_files:
        importer_id = _node_id(pf.path)
        for imp in pf.imports:
            # Try to resolve the import to another node in the codebase
            target_id = (
                module_to_node.get(imp.module)
                or module_to_node.get(imp.qualified_name)
                or stem_to_node.get(imp.module)
            )
            if target_id and target_id != importer_id:
                if target_id not in edges[importer_id]:
                    edges[importer_id].append(target_id)

    # ── Step 3: build reverse edges (importee → list of importers) ─────────
    # reverse_edges[nid] = list of nodes that directly import nid
    reverse_edges: dict[str, list[str]] = {nid: [] for nid in nodes}
    for importer, importees in edges.items():
        for importee in importees:
            if importer not in reverse_edges[importee]:
                reverse_edges[importee].append(importer)

    # ── Step 4: compute direct_dependents and transitive_dependents ────────
    for nid, node in nodes.items():
        node.direct_dependents = list(reverse_edges.get(nid, []))
        node.transitive_dependents = _compute_transitive(nid, reverse_edges)

    # ── Step 5: tag hits with node IDs and mark has_crypto ─────────────────
    hit_node_set: set[str] = set()
    for hit in hits:
        nid = _node_id(hit.location.file)
        if nid in nodes:
            hit.dependency_node_id = nid
            hit_node_set.add(nid)

    for nid in hit_node_set:
        nodes[nid].has_crypto = True

    graph = DependencyGraph(session_id=session_id, nodes=nodes, edges=edges)

    # ── Step 6 (optional): persist to Neo4j ────────────────────────────────
    _try_persist_neo4j(graph)

    return graph


# ---------------------------------------------------------------------------
# Neo4j persistence (optional — no error if NEO4J_URI unset)
# ---------------------------------------------------------------------------


def _try_persist_neo4j(graph: DependencyGraph) -> None:
    """
    Attempt to persist the DependencyGraph to Neo4j.

    If NEO4J_URI is not set, or the driver is unavailable, this function
    logs a debug message and returns cleanly.  It must never raise.
    """
    uri = os.environ.get("NEO4J_URI")
    if not uri:
        logger.debug("NEO4J_URI not set — skipping Neo4j persistence")
        return

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "")

    try:
        from neo4j import GraphDatabase
    except ImportError:
        logger.warning("neo4j driver not installed — skipping Neo4j persistence")
        return

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            _upsert_graph(session, graph)
        driver.close()
        logger.info("DependencyGraph persisted to Neo4j (session_id=%s)", graph.session_id)
    except Exception:
        logger.warning("Neo4j persistence failed — continuing in-memory only", exc_info=True)


def _upsert_graph(session: object, graph: DependencyGraph) -> None:
    """
    Write all nodes and edges to Neo4j.

    Node label: Module
    Relationships: IMPORTS_FROM, (CALLS — reserved for future use)
    All nodes are tagged with session_id for isolation.
    """
    from neo4j import Session  # noqa: PLC0415

    neo4j_session: Session = session  # type: ignore[assignment]

    for nid, node in graph.nodes.items():
        neo4j_session.run(
            """
            MERGE (m:Module {node_id: $node_id, session_id: $session_id})
            SET m.module_name   = $module_name,
                m.file          = $file,
                m.language      = $language,
                m.has_crypto    = $has_crypto
            """,
            node_id=nid,
            session_id=graph.session_id,
            module_name=node.module_name,
            file=str(node.file),
            language=node.language,
            has_crypto=node.has_crypto,
        )

    for importer_id, importee_ids in graph.edges.items():
        for importee_id in importee_ids:
            neo4j_session.run(
                """
                MATCH (a:Module {node_id: $importer, session_id: $session_id})
                MATCH (b:Module {node_id: $importee, session_id: $session_id})
                MERGE (a)-[:IMPORTS_FROM]->(b)
                """,
                importer=importer_id,
                importee=importee_id,
                session_id=graph.session_id,
            )
