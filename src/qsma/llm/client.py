"""
qsma.llm.client
===============
OpenAI-compatible LLM client for the Quantum-Safe Crypto Migration Agent.

PROVIDER AGNOSTIC — works with any provider that implements the OpenAI Chat
Completions API, including:
  - OpenAI          (default; leave LLM_BASE_URL blank)
  - Anthropic        (via OpenAI-compatible gateway)
  - IBM watsonx.ai   (via its /ml/v1/text/chat OpenAI-compatible endpoint)
  - Ollama / local   (LLM_BASE_URL=http://localhost:11434/v1)
  - Any other compatible provider

SWITCHING PROVIDER requires ONLY changing .env — zero code change.

Environment variables (all read at runtime from .env):
  LLM_API_KEY       — provider API key (required)
  LLM_BASE_URL      — base URL override (optional; blank = OpenAI default)
  LLM_MODEL         — model identifier (default: gpt-4o)
  LLM_MAX_TOKENS    — max tokens per request (default: 4096)
  LLM_TEMPERATURE   — generation temperature (default: 0.2)

USAGE IN MODULES:
  Do NOT import the openai SDK directly in Planner or Migrator.
  Always go through this client so the provider remains swappable and
  so tests can mock the client cleanly.

  from qsma.llm.client import LLMClient
  client = LLMClient()           # reads from env
  response = client.chat(messages)

TESTING:
  Inject a mock client in unit tests — LLMClient is not a singleton.
  No LLM_API_KEY is required for unit tests that mock the client.

ARCHITECTURAL NOTE (ADR-002):
  The LLM is used ONLY in Planner and Migrator.
  Detection, classification, and validation are deterministic — they never
  call this client.
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Prompt templates — stored here so they are versioned alongside the client.
# Each template is a function that returns a list[dict] (messages array).
# ---------------------------------------------------------------------------

def migration_plan_prompt(
    finding_summary: str,
    code_snippet: str,
    algorithm: str,
    target_algorithm: str,
) -> list[dict[str, str]]:
    """
    Prompt for the Planner module: generate a structured migration strategy
    for a finding that cannot be handled by deterministic rules.
    """
    return [
        {
            "role": "system",
            "content": (
                "You are a quantum-safe cryptography migration expert. "
                "You help developers migrate quantum-vulnerable cryptographic code "
                "to NIST-standardized post-quantum alternatives. "
                "Be precise, concise, and output only structured JSON when asked."
            ),
        },
        {
            "role": "user",
            "content": (
                f"I need to migrate the following cryptographic usage from {algorithm} "
                f"to {target_algorithm}.\n\n"
                f"Finding summary: {finding_summary}\n\n"
                f"Code snippet:\n```python\n{code_snippet}\n```\n\n"
                "Provide a migration plan as JSON with keys: "
                "'strategy_description', 'transformation_steps' (list of strings), "
                "'new_dependencies' (list of pip package names), "
                "'estimated_complexity' ('low'|'medium'|'high'), "
                "'caveats' (list of strings, may be empty)."
            ),
        },
    ]


def code_transform_prompt(
    original_code: str,
    algorithm: str,
    target_algorithm: str,
    transformation_hints: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Prompt for the Migrator module (LLM-assisted path): transform code from
    a quantum-vulnerable algorithm to a post-quantum alternative.
    """
    hints_text = "\n".join(f"- {k}: {v}" for k, v in transformation_hints.items())
    return [
        {
            "role": "system",
            "content": (
                "You are a Python code transformation expert specializing in "
                "quantum-safe cryptography migration. "
                "Output ONLY the transformed Python code — no explanations, "
                "no markdown fences, no commentary. Preserve all original "
                "comments, formatting, and non-cryptographic logic exactly."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Transform the following Python code from {algorithm} to "
                f"{target_algorithm}.\n\n"
                f"Transformation hints:\n{hints_text}\n\n"
                f"Original code:\n{original_code}\n\n"
                "Return only the transformed Python code."
            ),
        },
    ]


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Provider-agnostic OpenAI-compatible LLM client.

    All configuration is read from environment variables at instantiation time.
    Pass explicit values to override env vars (useful in tests).

    Parameters
    ----------
    api_key   : override LLM_API_KEY
    base_url  : override LLM_BASE_URL (None = use provider default)
    model     : override LLM_MODEL
    max_tokens: override LLM_MAX_TOKENS
    temperature: override LLM_TEMPERATURE
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.base_url = base_url or os.environ.get("LLM_BASE_URL") or None
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o")
        self.max_tokens = max_tokens or int(os.environ.get("LLM_MAX_TOKENS", "4096"))
        self.temperature = temperature if temperature is not None else float(
            os.environ.get("LLM_TEMPERATURE", "0.2")
        )

        # Lazy import — keeps openai as optional until actually used
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazily initialize the openai client on first use."""
        if self._client is None:
            try:
                from openai import OpenAI  # type: ignore[import]
            except ImportError as exc:
                raise ImportError(
                    "The 'openai' package is required for LLM features. "
                    "Install it with: pip install openai"
                ) from exc

            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        return self._client

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """
        Send a chat completion request and return the response text.

        Parameters
        ----------
        messages    : list of {"role": "system"|"user"|"assistant", "content": str}
        model       : override instance model for this request
        max_tokens  : override instance max_tokens for this request
        temperature : override instance temperature for this request

        Returns
        -------
        str — the assistant's reply text

        Raises
        ------
        LLMError — wraps any provider API error with a clean message
        """
        client = self._get_client()
        try:
            response = client.chat.completions.create(
                model=model or self.model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature if temperature is not None else self.temperature,
            )
            content = response.choices[0].message.content
            return content if content is not None else ""
        except Exception as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc


class LLMError(RuntimeError):
    """Raised when an LLM API call fails. Wraps the underlying provider error."""
