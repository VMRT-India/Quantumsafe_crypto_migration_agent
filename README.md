# Quantum-Safe Crypto Migration Agent

> IBM Dev Day Hackathon — Team Project

A CLI developer tool that analyzes codebases (Python, Java, Go, C, Rust) for quantum-vulnerable
cryptography, explains the risk, and automatically migrates vulnerable Python code to NIST
post-quantum standards using a LangGraph agentic loop backed by IBM watsonx.ai.

---

## What it does

```
qsma scan <path>               →  detect crypto findings across all supported languages
qsma report <path>             →  display a structured findings report
qsma migrate <path>            →  select findings and apply LLM-agentic quantum-safe migrations
qsma migrate --resume <id>     →  resume an interrupted migration from Redis session state
qsma validate <path>           →  validate migrated code builds and tests still pass
```

**Full workflow:**

```
Analyze → Detect → Explain → Prioritize → Select → Migrate → Validate → Report
```

---

## Quick start

```bash
# 1. Clone and set up environment
git clone <repo-url>
cd quantumsafe_crypto_migration_agent

# 2. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 3. Install
pip install -e ".[dev]"

# 4. Configure environment (NEVER commit .env)
cp .env.example .env
# Edit .env with your IBM watsonx.ai credentials

# 5. Install pre-commit hooks (security requirement)
pre-commit install

# 6. Verify installation
qsma --version
qsma --help
```

---

## Security requirements

- **Never commit `.env`** — it is in `.gitignore`
- **Never hardcode API keys** — use environment variables only
- Run `./scripts/check_secrets.sh` before every push
- Pre-commit hooks enforce secret scanning on every commit
- See `.env.example` for required environment variables (placeholders only)

---

## Architecture

See [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) — the master document for architecture,
module specifications, dependency graph, parallelization plan, and development phases.
See [`ARCHITECTURE.md`](ARCHITECTURE.md) — full pipeline diagram and file index.

```
CLI → Ingestion → Analyzer → Detector → Classifier
                 (tree-sitter,           (NIST risk table,
                  all languages)          no LLM)
                                               ↓
                              ┌────────────────────────────────┐
                              │  LangGraph MigrationGraph       │
                              │  (Redis session state)          │
                              │  Planner agent                  │
                              │    → Migrator agent             │
                              │      → Validator agent          │
                              │        → retry or pass          │
                              └────────────────┬───────────────┘
                                               ↓
                                           Reporter
```

---

## IBM technologies

- **watsonx.ai** — Granite Code model; default LLM backend for all three migration agents (Planner, Migrator, Validator)
- **IBM Cloud** — credential management via environment variables
- **LangGraph** — agentic orchestration over watsonx.ai (provider-agnostic; switch via `.env` only)

---

## Project structure

```
src/qsma/
├── cli/                   — Click commands (thin orchestration layer)
├── ingestion/             — Filesystem walk, language detection, source file collection
├── analyzer/              — tree-sitter (all languages) + libcst CST builder (Python only)
├── detector/              — tree-sitter query pattern-matching for crypto usage (all languages)
├── classifier/            — Quantum risk scoring via NIST risk table (no LLM)
├── planner/               — LangGraph agent node: LLM reasons migration strategy per finding
├── migrator/              — LangGraph agent node: LLM generates transformed code; libcst splices it in
├── validator/             — LangGraph agent node: syntax/test check + LLM failure analysis + retry signal
├── reporter/              — Terminal/JSON/Markdown output formatting
├── agent/                 — LangGraph StateGraph wiring (planner→migrator→validator loop)
├── llm/
│   ├── client.py          — watsonx.ai / OpenAI / Anthropic provider-agnostic wrapper
│   └── training_data/     — Few-shot migration examples + agent system prompts (JSON/txt)
└── utils/
    ├── models.py          — Shared Pydantic contracts (CryptoFinding, MigrationSessionState, …)
    └── session.py         — Redis session manager (MigrationSessionState persistence + resume)

tests/
├── unit/         — Per-module unit tests
├── integration/  — Multi-module pipeline tests
├── e2e/          — Full CLI end-to-end tests
└── fixtures/     — Sample vulnerable projects for testing (deliberately vulnerable)
```

---

## Development

```bash
# Run all tests
pytest

# Lint
ruff check src/ tests/

# Type check
mypy src/

# Security check (run before commits)
./scripts/check_secrets.sh
```

---

## License

Apache-2.0
