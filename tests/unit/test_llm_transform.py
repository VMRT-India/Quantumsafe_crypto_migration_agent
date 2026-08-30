"""
Unit tests for qsma.migrator.llm_transform, focused on _reindent_to_match.

Background: discovered during a live end-to-end test against real PyJWT
source with a real LLM (Groq/gpt-oss-120b) — the model reliably dedents its
"return only the code" replies to column 0 (or emits inconsistent per-line
indentation when expanding one statement into several), which breaks
patcher.apply_patch's line-range splice since Python is indentation-sensitive.

Covers:
  - Single-line original: output is force-flattened to one uniform indent
    level, ignoring whatever relative indentation the model invented.
  - Multi-line original: the model's block is dedented to its own minimum
    common indent, then the target base indent is re-applied, preserving
    relative internal nesting.
  - No original snippet / no leading indent: passthrough, no crash.
  - call_llm_transform end-to-end applies reindenting to the LLM response.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from qsma.migrator.llm_transform import _reindent_to_match, call_llm_transform
from qsma.utils.models import Algorithm, MigrationPlan


def test_single_line_original_flattens_inconsistent_indentation():
    original = "            signature: bytes = key.sign(msg, padding.PKCS1v15(), self.hash_alg())"
    # Model output: first two lines correctly indented, third over-indented —
    # the exact pattern observed from the real LLM response.
    transformed = (
        "            # QSMA: requires pqcrypto\n"
        "            from pqcrypto.sign.dilithium2 import sign\n"
        "                        signature: bytes = sign(key, msg)"
    )
    result = _reindent_to_match(transformed, original)
    for line in result.splitlines():
        assert line.startswith("            ") and not line.startswith("             ")


def test_single_line_original_reindents_fully_dedented_response():
    original = "        signature: bytes = key.sign(msg)"
    transformed = "signature: bytes = dilithium2.sign(msg, key)"
    result = _reindent_to_match(transformed, original)
    assert result == "        signature: bytes = dilithium2.sign(msg, key)"


def test_multiline_original_preserves_relative_nesting():
    original = "    def sign(self, key):\n        return key.sign(msg)"
    # Model's block is internally consistent (its own 4-space nesting) but
    # dedented to column 0 overall.
    transformed = "def sign(self, key):\n    return key.sign(msg)"
    result = _reindent_to_match(transformed, original)
    lines = result.splitlines()
    assert lines[0] == "    def sign(self, key):"
    assert lines[1] == "        return key.sign(msg)"


def test_no_original_snippet_is_passthrough():
    assert _reindent_to_match("some code", "") == "some code"


def test_no_leading_indent_is_passthrough():
    original = "signature = key.sign(msg)"
    transformed = "    signature = dilithium2.sign(msg, key)"
    assert _reindent_to_match(transformed, original) == transformed


def make_plan(finding_id: str = "QSMA-0001") -> MigrationPlan:
    return MigrationPlan(
        finding_id=finding_id,
        strategy="llm_assisted",
        target_algorithm=Algorithm.DILITHIUM,
        description="Migrate RSA signing to ML-DSA",
        estimated_complexity="medium",
        transformation_hints={"source_algorithm": "RSA"},
    )


def test_call_llm_transform_reindents_response():
    original = "            signature: bytes = key.sign(msg, padding.PKCS1v15(), self.hash_alg())"
    llm = MagicMock()
    llm.chat.return_value = "signature: bytes = dilithium2.sign(msg, key)"

    success, code = call_llm_transform(make_plan(), original, llm)

    assert success is True
    assert code == "            signature: bytes = dilithium2.sign(msg, key)"


def test_call_llm_transform_manual_required_not_reindented():
    llm = MagicMock()
    llm.chat.return_value = "# QSMA_MANUAL_REQUIRED: no safe automatic transform"

    success, code = call_llm_transform(make_plan(), "    x = 1", llm)

    assert success is False
    assert code.startswith("# QSMA_MANUAL_REQUIRED:")
