# Quantum-Safe Crypto Migration Agent

> IBM Dev Day Hackathon — Team Project

A CLI developer tool that analyzes codebases (Python, Java, Go, C, Rust) for quantum-vulnerable
cryptography, explains the risk, and automatically migrates vulnerable Python code to NIST
post-quantum standards using a LangGraph agentic loop backed by IBM watsonx.ai.

---

## What it does

```
qsma scan <path>                          →  detect crypto findings, build dependency graph, dual risk scores
qsma migrate <path> --finding-id ID       →  migrate specific finding(s) by ID
qsma migrate <path> --auto                →  auto-select every CRITICAL/HIGH finding and migrate
qsma migrate <path> --resume <id>         →  resume an interrupted migration session
qsma validate <path>                      →  validate migrated code: syntax check + test run
qsma report <path> [--findings file.json] →  display a structured findings report
qsma chat <path>                          →  (placeholder — natural-language advisor, not yet implemented)
```

**Working end-to-end today:**

```
Scan → Detect → Build dependency graph → Dual-score classify
  → Select findings (--finding-id / --auto) → Migrate (Planner→Migrator→Validator agents,
    real LangGraph loop with retry/escalation) → Validate → Report
```

Verified against real open-source codebases (not just the bundled fixtures) with a
real LLM — see `bob_sessions/` for the demo walkthrough. `qsma chat` (natural-language
finding selection) is a stretch goal, not required for the flow above.

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
# Edit .env with your LLM credentials — watsonx.ai is the default provider,
# but any openai_compatible endpoint works too (verified against Groq:
# set LLM_PROVIDER=openai_compatible, LLM_BASE_URL, LLM_API_KEY, LLM_MODEL).

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
CLI → Ingestion → Analyzer → Detector ──────────────────────────────────────────────┐
                             (tree-sitter     Phase A: list[CryptoHit]               │
                              all languages)  Phase B: DependencyGraph → Neo4j       │
                                                        (blast radius per module)    │
                                                   ↓                                 │
                                            Classifier                               │
                                    Score 1: algorithm_risk_score                    │
                                    (hard-coded NIST table — no LLM)                │
                                    Score 2: migration_risk_score                    │
                                    (LLM-assisted, uses blast_radius from graph)     │
                                             ↓ list[CryptoFinding]                   │
                              ┌──────────────────────────────────────┐               │
                              │  LangGraph MigrationGraph            │ ←─────────────┘
                              │  (Redis session state)               │  DependencyGraph
                              │  Planner agent (queries Neo4j)       │
                              │    → Migrator agent                  │
                              │      → Validator agent               │
                              │        → retry or pass               │
                              └──────────────────┬───────────────────┘
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
├── detector/              — tree-sitter pattern-matching for crypto + DependencyGraph builder (Neo4j)
├── classifier/            — Dual risk scoring: algorithm_risk (NIST table) + migration_risk (LLM-assisted)
├── advisor/               — placeholder (qsma chat); natural-language finding selection is a stretch goal
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
    └── session.py         — session store (MigrationSessionState persistence + resume); in-memory today, same interface Redis will use

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
