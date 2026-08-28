# Quantum-Safe Crypto Migration Agent

> IBM Dev Day Hackathon — Team Project

A CLI developer tool that analyzes Python codebases for quantum-vulnerable cryptography,
explains the risk, and automatically migrates vulnerable code to NIST post-quantum standards.

---

## What it does

```
qsma scan <path>      →  detect crypto findings (RSA, ECDSA, ECDH, DES, AES-128, …)
qsma report <path>    →  display a structured findings report
qsma migrate <path>   →  interactively select and apply quantum-safe migrations
qsma validate <path>  →  validate migrated code builds and tests still pass
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

```
CLI → Ingestion → Analyzer → Detector → Classifier → Reporter
                                                    ↓
                                              Planner → Migrator → Validator → Reporter
```

---

## IBM technologies

- **watsonx.ai** — Granite Code model for LLM-assisted migration planning
- **IBM Cloud** — credential management via environment variables

---

## Project structure

```
src/qsma/
├── cli/          — Click commands (thin orchestration layer)
├── ingestion/    — Filesystem walk, source file collection
├── analyzer/     — AST parsing, call graph extraction (libcst)
├── detector/     — Pattern-matching for crypto usage sites
├── classifier/   — Quantum risk scoring and recommendations
├── planner/      — Migration strategy selection
├── migrator/     — Code transformation (deterministic AST + LLM fallback)
├── validator/    — Post-migration build/test validation
├── reporter/     — Terminal/JSON/Markdown output formatting
├── llm/          — watsonx.ai client wrapper
└── utils/        — Shared Pydantic data models (inter-module contracts)

tests/
├── unit/         — Per-module unit tests
├── integration/  — Multi-module pipeline tests
├── e2e/          — Full CLI end-to-end tests
└── fixtures/     — Sample vulnerable Python projects for testing
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
