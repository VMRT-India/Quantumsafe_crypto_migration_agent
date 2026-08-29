"""
src/qsma/detector/patterns/__init__.py
========================================
Aggregates all pattern libraries into a single ALL_RULES list.

Import this list in the Detector to apply every rule.
"""

from __future__ import annotations

from qsma.detector.patterns.ecc import ECC_RULES
from qsma.detector.patterns.hashing import HASHING_RULES
from qsma.detector.patterns.rsa import RSA_RULES
from qsma.detector.patterns.symmetric import SYMMETRIC_RULES
from qsma.utils.models import DetectionRule

ALL_RULES: list[DetectionRule] = [
    *RSA_RULES,
    *ECC_RULES,
    *SYMMETRIC_RULES,
    *HASHING_RULES,
]

__all__ = ["ALL_RULES"]
