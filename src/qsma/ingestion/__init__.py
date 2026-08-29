"""
qsma.ingestion
==============
Public API for the Ingestion module.

Usage::

    from qsma.ingestion import collect_snapshot, IngestionConfig
    snapshot = collect_snapshot(Path("/my/project"))
"""

from qsma.ingestion.walker import collect_snapshot

__all__ = ["collect_snapshot"]
