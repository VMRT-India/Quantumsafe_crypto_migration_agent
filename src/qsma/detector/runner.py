"""
qsma.detector.runner
=====================
Phase A: Apply all DetectionRule instances from the patterns library to every
ParsedFile in an AnalysisResult, producing a flat list[CryptoHit].

No risk scoring happens here — that is the Classifier's job.
"""

from __future__ import annotations

import logging

from qsma.detector.patterns import ALL_RULES
from qsma.utils.models import AnalysisResult, CryptoHit, DetectionRule, ParsedFile

logger = logging.getLogger(__name__)


def apply_rules(
    pf: ParsedFile,
    rules: list[DetectionRule] | None = None,
) -> list[CryptoHit]:
    """
    Apply detection rules to a single ParsedFile and return all matching CryptoHits.

    Parameters
    ----------
    pf:
        A parsed source file from the Analyzer.
    rules:
        Rules to apply; defaults to ALL_RULES from the patterns library.

    Returns
    -------
    list[CryptoHit]
        All hits produced by all matching rules (may include duplicates if
        multiple rules fire for the same location — deduplication happens
        in the top-level detect() function).
    """
    if rules is None:
        rules = ALL_RULES

    hits: list[CryptoHit] = []
    for rule in rules:
        try:
            result = rule.matcher_fn(pf)
            hits.extend(result)
        except Exception:
            logger.exception("Rule %s raised an exception on %s", rule.rule_id, pf.path)
    return hits


def run_detection(
    analysis: AnalysisResult,
    rules: list[DetectionRule] | None = None,
) -> list[CryptoHit]:
    """
    Run all detection rules over every file in an AnalysisResult.

    Parameters
    ----------
    analysis:
        The output of the Analyzer.
    rules:
        Explicit rule list (defaults to ALL_RULES).

    Returns
    -------
    list[CryptoHit]
        Deduplicated hits, sorted by (file, line_start, rule_id).
    """
    all_hits: list[CryptoHit] = []
    for pf in analysis.parsed_files:
        hits = apply_rules(pf, rules)
        logger.debug("File %s (%s): %d hit(s)", pf.path, pf.language, len(hits))
        all_hits.extend(hits)

    # Deduplicate: same (file, line_start, rule_id) should not appear twice.
    seen: set[tuple[str, int, str]] = set()
    deduplicated: list[CryptoHit] = []
    for hit in all_hits:
        key = (str(hit.location.file), hit.location.line_start, hit.rule_id)
        if key not in seen:
            seen.add(key)
            deduplicated.append(hit)

    # Deterministic sort
    deduplicated.sort(key=lambda h: (str(h.location.file), h.location.line_start, h.rule_id))
    return deduplicated
