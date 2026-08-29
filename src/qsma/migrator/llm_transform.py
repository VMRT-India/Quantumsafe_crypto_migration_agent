"""
qsma.migrator.llm_transform
============================
Prompt builder and LLM response parser for the Migrator node.

Builds the transformation prompt from a MigrationPlan + original snippet +
few-shot examples, calls LLMClient, and returns the transformed code string.

ADR-002: All transformation logic comes from the LLM — this module only
         constructs the prompt context and extracts the code from the response.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from qsma.llm.client import LLMClient, LLMError
from qsma.utils.models import MigrationPlan

logger = logging.getLogger(__name__)

_MANUAL_REQUIRED_MARKER = "# QSMA_MANUAL_REQUIRED:"


def _load_system_prompt() -> str:
    prompt_path = (
        Path(__file__).parent.parent / "llm" / "training_data" / "prompts" / "migrator_system.txt"
    )
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8").strip()
    return (
        "You are a Python code transformation engine. "
        "Output ONLY the transformed Python code — no explanations."
    )


def _load_few_shot(plan: MigrationPlan) -> list[dict[str, Any]]:
    """Load few-shot examples relevant to this plan's algorithm pair."""
    slug_map = {
        "RSA":    "rsa_to_ml_dsa",
        "ECDSA":  "ecdsa_to_ml_dsa",
        "ECDH":   "ecdh_to_ml_kem",
        "AES-128": "aes128_to_aes256",
    }
    hints = plan.transformation_hints
    src_alg = hints.get("source_algorithm", "")
    slug = slug_map.get(src_alg, "unknown_pattern")
    few_shot_path = (
        Path(__file__).parent.parent
        / "llm" / "training_data" / "few_shot" / f"{slug}.json"
    )
    if not few_shot_path.exists():
        return []
    try:
        data = json.loads(few_shot_path.read_text(encoding="utf-8"))
        return data.get("examples", [])
    except Exception:
        return []


def build_transform_messages(
    plan: MigrationPlan,
    original_snippet: str,
    retry_hints: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """
    Build the LLM message list for a code transformation request.

    Parameters
    ----------
    plan             : MigrationPlan produced by the Planner
    original_snippet : the exact code to transform (from CryptoFinding.location.snippet
                       or the full extracted function/block)
    retry_hints      : optional dict from Validator on a retry attempt
    """
    system_prompt = _load_system_prompt()

    hints = plan.transformation_hints
    hints_text = "\n".join(f"  {k}: {v}" for k, v in hints.items()) if hints else "  (none)"

    few_shots = _load_few_shot(plan)
    few_shot_block = ""
    if few_shots:
        few_shot_block = "\n\nFew-shot examples (input→output pairs):\n" + json.dumps(few_shots, indent=2)

    retry_block = ""
    if retry_hints:
        retry_text = "\n".join(f"  {k}: {v}" for k, v in retry_hints.items())
        retry_block = f"\n\nRetry hints from validator:\n{retry_text}"

    user_msg = (
        f"Migration plan for finding {plan.finding_id}:\n"
        f"  Source algorithm: {hints.get('source_algorithm', 'see snippet')}\n"
        f"  Target algorithm: {plan.target_algorithm.value}\n"
        f"  Description: {plan.description}\n"
        f"\nTransformation hints:\n{hints_text}"
        f"{few_shot_block}"
        f"{retry_block}"
        f"\n\nOriginal code to transform:\n{original_snippet}\n\n"
        "Return ONLY the transformed Python code."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]


def call_llm_transform(
    plan: MigrationPlan,
    original_snippet: str,
    llm: LLMClient,
    retry_hints: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """
    Call the LLM to transform *original_snippet* according to *plan*.

    Returns
    -------
    (success: bool, code_or_error: str)
      success=True  → code_or_error is the transformed code
      success=False → code_or_error is the error / manual-required message
    """
    messages = build_transform_messages(plan, original_snippet, retry_hints)

    try:
        response = llm.chat(messages)
    except LLMError as exc:
        return False, f"LLM call failed: {exc}"

    # Strip any accidental markdown fences the model might output
    response = _strip_fences(response).strip()

    if response.startswith(_MANUAL_REQUIRED_MARKER):
        return False, response

    return True, response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove leading/trailing ```python ... ``` or ``` ... ``` fences."""
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)
