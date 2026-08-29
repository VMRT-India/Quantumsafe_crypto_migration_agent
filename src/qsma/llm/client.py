"""
qsma.llm.client
===============
LLM client for the Quantum-Safe Crypto Migration Agent.

DEFAULT PROVIDER: IBM watsonx.ai (Granite Code model)
  - Used via the ibm-watsonx-ai SDK
  - Credentials: WATSONX_API_KEY, WATSONX_PROJECT_ID, WATSONX_URL
  - Model: WATSONX_MODEL (default: ibm/granite-34b-code-instruct)

OPTIONAL COMPATIBLE PROVIDERS:
  Set LLM_PROVIDER in .env to switch. No code change required.

  "openai_compatible"   — any provider with an OpenAI-compatible Chat
                          Completions endpoint (OpenAI, Azure OpenAI,
                          local Ollama, any compatible gateway)
                          Requires: pip install qsma[llm-openai]

  "anthropic_compatible" — any provider with an Anthropic-compatible
                           Messages endpoint
                           Requires: pip install qsma[llm-anthropic]

SWITCHING PROVIDER: change LLM_PROVIDER (and matching credentials) in .env.
Zero code change required.

Environment variables — see .env.example for full reference:

  watsonx.ai (default):
    WATSONX_API_KEY        — IBM Cloud API key
    WATSONX_PROJECT_ID     — watsonx.ai project ID
    WATSONX_URL            — service URL (default: us-south)
    WATSONX_MODEL          — model ID (default: ibm/granite-34b-code-instruct)

  openai_compatible:
    LLM_API_KEY            — provider API key (any OpenAI-compatible key)
    LLM_BASE_URL           — provider base URL
    LLM_MODEL              — model identifier

  anthropic_compatible:
    LLM_API_KEY            — provider API key (any Anthropic-compatible key)
    LLM_BASE_URL           — provider base URL (if non-default)
    LLM_MODEL              — model identifier

  shared:
    LLM_PROVIDER           — "watsonx" | "openai_compatible" | "anthropic_compatible"
    LLM_MAX_TOKENS         — max tokens per request (default: 4096)
    LLM_TEMPERATURE        — generation temperature (default: 0.2)

USAGE IN MODULES:
  Do NOT import provider SDKs directly in Planner or Migrator.
  Always go through this client.

  from qsma.llm.client import LLMClient
  client = LLMClient()           # reads provider + credentials from env
  response = client.chat(messages)

TESTING:
  Inject a mock: LLMClient(provider="mock") or monkeypatch client.chat().
  No real credentials required for unit tests.

ARCHITECTURAL NOTE (ADR-002):
  The LLM is used ONLY in Planner and Migrator.
  Detection, classification, and validation are always deterministic.
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Provider constants
# ---------------------------------------------------------------------------

PROVIDER_WATSONX = "watsonx"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
PROVIDER_ANTHROPIC_COMPATIBLE = "anthropic_compatible"
PROVIDER_MOCK = "mock"  # for unit tests

_VALID_PROVIDERS = {
    PROVIDER_WATSONX,
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_ANTHROPIC_COMPATIBLE,
    PROVIDER_MOCK,
}

# ---------------------------------------------------------------------------
# Prompt templates
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
    Returns a messages list compatible with both OpenAI and Anthropic formats.
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
    Provider-agnostic LLM client.

    Default provider: IBM watsonx.ai (Granite Code model).
    Optional providers: openai_compatible, anthropic_compatible.

    All configuration is read from environment variables at instantiation.
    Pass explicit values to override env vars (useful in tests).

    Parameters
    ----------
    provider    : "watsonx" | "openai_compatible" | "anthropic_compatible" | "mock"
                  Default: value of LLM_PROVIDER env var, falling back to "watsonx"
    api_key     : provider API key (overrides WATSONX_API_KEY or LLM_API_KEY)
    base_url    : endpoint base URL override (for compatible providers)
    model       : model identifier override
    max_tokens  : max tokens per request
    temperature : generation temperature
    """

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> None:
        self.provider = (provider or os.environ.get("LLM_PROVIDER", PROVIDER_WATSONX)).lower()

        if self.provider not in _VALID_PROVIDERS:
            raise ValueError(
                f"Unknown LLM_PROVIDER '{self.provider}'. "
                f"Valid values: {sorted(_VALID_PROVIDERS)}"
            )

        self.max_tokens = max_tokens or int(os.environ.get("LLM_MAX_TOKENS", "4096"))
        self.temperature = (
            temperature
            if temperature is not None
            else float(os.environ.get("LLM_TEMPERATURE", "0.2"))
        )

        # Provider-specific config
        if self.provider == PROVIDER_WATSONX:
            self.api_key = api_key or os.environ.get("WATSONX_API_KEY", "")
            self.base_url = base_url or os.environ.get(
                "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
            )
            self.model = model or os.environ.get("WATSONX_MODEL", "ibm/granite-34b-code-instruct")
            self.project_id = os.environ.get("WATSONX_PROJECT_ID", "")
        else:
            # openai_compatible or anthropic_compatible
            self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
            self.base_url = base_url or os.environ.get("LLM_BASE_URL") or None
            self.model = model or os.environ.get("LLM_MODEL", "")
            self.project_id = ""

        # Lazy-initialized SDK client
        self._client: Any = None

    # ------------------------------------------------------------------
    # Internal: provider-specific client initializers
    # ------------------------------------------------------------------

    def _init_watsonx(self) -> Any:
        """Initialize the ibm-watsonx-ai client."""
        try:
            from ibm_watsonx_ai import Credentials  # type: ignore[import]
            from ibm_watsonx_ai.foundation_models import ModelInference  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "ibm-watsonx-ai is required for the watsonx provider. "
                "It is installed by default: pip install qsma"
            ) from exc

        credentials = Credentials(url=self.base_url, api_key=self.api_key)
        return ModelInference(
            model_id=self.model,
            credentials=credentials,
            project_id=self.project_id,
        )

    def _init_openai_compatible(self) -> Any:
        """Initialize an OpenAI-compatible client (openai SDK)."""
        try:
            from openai import OpenAI  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "The openai package is required for the openai_compatible provider. "
                "Install it with: pip install 'qsma[llm-openai]'"
            ) from exc

        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def _init_anthropic_compatible(self) -> Any:
        """Initialize an Anthropic-compatible client (anthropic SDK)."""
        try:
            from anthropic import Anthropic  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "The anthropic package is required for the anthropic_compatible provider. "
                "Install it with: pip install 'qsma[llm-anthropic]'"
            ) from exc

        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return Anthropic(**kwargs)

    def _get_client(self) -> Any:
        """Lazily initialize the provider SDK client on first use."""
        if self._client is None:
            if self.provider == PROVIDER_WATSONX:
                self._client = self._init_watsonx()
            elif self.provider == PROVIDER_OPENAI_COMPATIBLE:
                self._client = self._init_openai_compatible()
            elif self.provider == PROVIDER_ANTHROPIC_COMPATIBLE:
                self._client = self._init_anthropic_compatible()
            # PROVIDER_MOCK: _client stays None; chat() returns a stub
        return self._client

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """
        Send a chat request and return the assistant's reply as a string.

        The messages format follows the OpenAI convention:
          [{"role": "system"|"user"|"assistant", "content": "..."}]
        This is normalised to the Anthropic format internally when needed.

        Parameters
        ----------
        messages    : conversation messages list
        model       : per-request model override
        max_tokens  : per-request token limit override
        temperature : per-request temperature override

        Returns
        -------
        str — the model's reply text

        Raises
        ------
        LLMError — wraps any provider SDK error with a clean message
        """
        _model = model or self.model
        _max_tokens = max_tokens or self.max_tokens
        _temp = temperature if temperature is not None else self.temperature

        # Mock provider — for unit tests, returns a fixed stub string
        if self.provider == PROVIDER_MOCK:
            return '{"strategy_description":"mock","transformation_steps":[],"new_dependencies":[],"estimated_complexity":"low","caveats":[]}'

        client = self._get_client()

        try:
            if self.provider == PROVIDER_WATSONX:
                return self._chat_watsonx(client, messages, _model, _max_tokens, _temp)
            elif self.provider == PROVIDER_OPENAI_COMPATIBLE:
                return self._chat_openai(client, messages, _model, _max_tokens, _temp)
            elif self.provider == PROVIDER_ANTHROPIC_COMPATIBLE:
                return self._chat_anthropic(client, messages, _model, _max_tokens, _temp)
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(f"LLM request failed [{self.provider}]: {exc}") from exc

        return ""  # unreachable

    # ------------------------------------------------------------------
    # Provider-specific chat implementations
    # ------------------------------------------------------------------

    def _chat_watsonx(
        self,
        client: Any,
        messages: list[dict[str, str]],
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """Call ibm-watsonx-ai ModelInference.chat()."""
        response = client.chat(
            messages=messages,
            params={
                "max_new_tokens": max_tokens,
                "temperature": temperature,
            },
        )
        # ibm-watsonx-ai returns: response["choices"][0]["message"]["content"]
        return str(response["choices"][0]["message"]["content"])

    def _chat_openai(
        self,
        client: Any,
        messages: list[dict[str, str]],
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """Call openai SDK ChatCompletion."""
        response = client.chat.completions.create(
            model=model,
            messages=messages,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=temperature,
        )
        content = response.choices[0].message.content
        return content if content is not None else ""

    def _chat_anthropic(
        self,
        client: Any,
        messages: list[dict[str, str]],
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """
        Call anthropic SDK Messages API.
        Splits the system message out (Anthropic requires it separately).
        """
        system_content = ""
        user_messages: list[dict[str, str]] = []

        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                user_messages.append(msg)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_messages,
        }
        if system_content:
            kwargs["system"] = system_content

        response = client.messages.create(**kwargs)
        return str(response.content[0].text)


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class LLMError(RuntimeError):
    """Raised when an LLM API call fails. Wraps the underlying provider error."""
