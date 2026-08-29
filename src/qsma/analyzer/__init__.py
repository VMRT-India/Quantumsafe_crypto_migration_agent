"""
qsma.analyzer
=============
Public API for the Analyzer module.

Usage::

    from qsma.analyzer import analyse_snapshot
    result = analyse_snapshot(snapshot)
"""

from qsma.analyzer.parser import analyse_snapshot, parse_file

__all__ = ["analyse_snapshot", "parse_file"]
