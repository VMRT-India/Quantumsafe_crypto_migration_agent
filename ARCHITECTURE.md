# ARCHITECTURE.md
## Quantum-Safe Crypto Migration Agent — Current Architecture & File Index

> **Purpose of this file:**
> 1. **File index** — what every file in the project contains, for fast AI orientation
> 2. **Current pipeline architecture** on `main` — the agreed design as implemented
> 3. **Per-branch architecture state** — what each branch currently has beyond `main`
>
> **AI rule:** Read this file at the start of every session. Update your branch's row in
> the [Branch state table](#per-branch-architecture-state) in the **same commit** as your
> implementation. When merging into `main`, update the `main` row and resolve the branch
> rows accordingly.
>
> **Module ownership and task allocation:** see `PROJECT_CONTEXT.md §10`.
> **Full module specifications and contracts:** see `PROJECT_CONTEXT.md §5–7`.

---

## Current state on `main`

**Phase:** 0 — Foundation complete  
**Last updated:** 2025-08-29  
**What is implemented:** Repo skeleton, shared contracts, stub CLI, LLM client, test fixtures.  
**What is NOT yet implemented:** All pipeline module logic (ingestion through reporter are empty stubs).

---

## File Index

### Planning & documentation

| File | What it contains |
|---|---|
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | **Master source of truth.** 18 sections: product overview, architecture, every module spec, inter-module contracts, task DAG, parallelization plan, 4-person allocation, Git strategy, phases, testing strategy, tech decisions, ADR log, known risks, current status, next tasks. Read before any work. |
| [`PROMPT.md`](PROMPT.md) | **Mandatory AI session bootstrap.** Step-by-step orientation checklist, branch table, screenshot workflow, DO-NOT-DO rules, DAG flexibility note, commit message convention, LLM provider reference, security rules, quick-reference table. Read first, every session. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | This file. File index + current pipeline architecture + per-branch state. |
| [`README.md`](README.md) | Project overview, quick-start install and usage, repo structure summary, security rules. |

### Configuration & security

| File | What it contains |
|---|---|
| [`.env.example`](.env.example) | All required environment variables with placeholder values only. Three sections: watsonx.ai (default), openai_compatible (optional), anthropic_compatible (optional). Copy to `.env` and fill in real values — never commit `.env`. |
| [`.gitignore`](.gitignore) | IBM security-required ignore patterns (credentials, `.env`, API key files) + standard Python ignores + `.qsma_cache/`. `bob_sessions/` is explicitly NOT ignored. |
| [`.bobignore`](.bobignore) | Prevents Bob AI from reading sensitive files (`.env`, credentials). |
| [`.pre-commit-config.yaml`](.pre-commit-config.yaml) | Pre-commit hooks: `detect-secrets` (blocks accidental credential commits) + `ruff` (linting). Run `pre-commit install` on first clone. |
| [`scripts/check_secrets.sh`](scripts/check_secrets.sh) | Pre-push security gate. Run before every `git push`. Checks for `.env` staged, credential patterns, and `detect-secrets` scan. |
| [`pyproject.toml`](pyproject.toml) | Package metadata, dependencies (`ibm-watsonx-ai` core; `[llm-openai]` and `[llm-anthropic]` optional extras), CLI entry point (`qsma = "qsma.cli.main:cli"`), ruff/mypy/pytest config. |

### Source — `src/qsma/`

| File | Status | What it contains |
|---|---|---|
| [`src/qsma/__init__.py`](src/qsma/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/cli/__init__.py`](src/qsma/cli/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/cli/main.py`](src/qsma/cli/main.py) | ✅ Implemented | **CLI entry point.** Click group `cli` with 4 sub-commands: `scan(path, fmt, output)`, `report(path, findings)`, `migrate(path, finding_id, dry_run, auto)`, `validate(path, timeout)`. All commands respond but delegate no logic yet — each prints a stub message. Uses `rich.console.Console` for output. |
| [`src/qsma/utils/__init__.py`](src/qsma/utils/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/utils/models.py`](src/qsma/utils/models.py) | ✅ Implemented | **Canonical inter-module contracts (Pydantic).** Do NOT redefine these in individual modules. Contains: `QuantumRisk` enum (CRITICAL/HIGH/MEDIUM/LOW/INFO), `Algorithm` enum (RSA, ECDSA, ECDH, DSA, DH, AES-128/256, DES, 3DES, MD5, SHA-1/256/384/512, post-quantum targets ML-KEM/ML-DSA/FN-DSA/SLH-DSA), `MigrationStatus` enum, `CodeLocation` model (file, line_start, line_end, column, snippet), `CryptoFinding` model (id, algorithm, risk, location, usage_type, library, severity_score, explanation, recommendation, migration_status), `MigrationPlan` model (finding_id, strategy, target_algorithm, description, complexity, dependencies, hints), `TransformationResult` model (finding_id, success, original/transformed snippet, files_modified, error), `ValidationResult` model (passed, build_ok, tests_ok, summary, regressions, warnings), `ScanReport` model (target_path, findings list, counts, transformation_results, validation_result, duration). |
| [`src/qsma/llm/__init__.py`](src/qsma/llm/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/llm/client.py`](src/qsma/llm/client.py) | ✅ Implemented | **Provider-agnostic LLM client.** Class `LLMClient(provider, api_key, base_url, model, max_tokens, temperature)`. Public method: `chat(messages, model, max_tokens, temperature) → str`. Internal methods: `_init_watsonx()`, `_init_openai_compatible()`, `_init_anthropic_compatible()`, `_get_client()` (lazy init), `_chat_watsonx()`, `_chat_openai()`, `_chat_anthropic()`. Prompt-builder functions: `migration_plan_prompt(finding_summary, code_snippet, algorithm, target_algorithm) → list[dict]`, `code_transform_prompt(original_code, algorithm, target_algorithm, hints) → list[dict]`. Error class: `LLMError(RuntimeError)`. Providers: `watsonx` (default, `ibm-watsonx-ai` SDK), `openai_compatible` (`openai` SDK, any compatible endpoint), `anthropic_compatible` (`anthropic` SDK), `mock` (returns stub JSON for unit tests). Switch provider via `LLM_PROVIDER` env var — zero code change. |
| [`src/qsma/ingestion/__init__.py`](src/qsma/ingestion/__init__.py) | 🔲 Stub | Empty. Planned: file walker, `CodebaseSnapshot`, `IngestionConfig`. |
| [`src/qsma/analyzer/__init__.py`](src/qsma/analyzer/__init__.py) | 🔲 Stub | Empty. Planned: AST parser (libcst), call graph builder, `AnalyzedCodebase`. |
| [`src/qsma/detector/__init__.py`](src/qsma/detector/__init__.py) | 🔲 Stub | Empty. Planned: pattern matching against `AnalyzedCodebase`, produces `list[CryptoHit]`. |
| [`src/qsma/classifier/__init__.py`](src/qsma/classifier/__init__.py) | 🔲 Stub | Empty. Planned: quantum risk scoring, severity, produces `list[CryptoFinding]`. |
| [`src/qsma/planner/__init__.py`](src/qsma/planner/__init__.py) | 🔲 Stub | Empty. Planned: per-finding strategy selection (deterministic or LLM-assisted), produces `MigrationPlan`. |
| [`src/qsma/migrator/__init__.py`](src/qsma/migrator/__init__.py) | 🔲 Stub | Empty. Planned: libcst AST transforms (deterministic path) + LLM-assisted rewrite (complex cases), produces `TransformationResult`. |
| [`src/qsma/validator/__init__.py`](src/qsma/validator/__init__.py) | 🔲 Stub | Empty. Planned: build check, test runner, regression detection, produces `ValidationResult`. |
| [`src/qsma/reporter/__init__.py`](src/qsma/reporter/__init__.py) | 🔲 Stub | Empty. Planned: CLI output formatter (text/JSON/markdown), consumes `ScanReport`. |

### Tests

| File | What it contains |
|---|---|
| [`tests/__init__.py`](tests/__init__.py) | Package marker. Empty. |
| [`tests/conftest.py`](tests/conftest.py) | Shared pytest fixtures: `sample_rsa_code()` → RSA signing snippet (quantum-vulnerable), `sample_ecdh_code()` → ECDH key exchange snippet (quantum-vulnerable), `tmp_project(tmp_path)` → minimal temp project directory structure. |
| [`tests/unit/__init__.py`](tests/unit/__init__.py) | Package marker. Empty. Unit tests go here. |
| [`tests/integration/__init__.py`](tests/integration/__init__.py) | Package marker. Empty. Integration tests go here. |
| [`tests/e2e/__init__.py`](tests/e2e/__init__.py) | Package marker. Empty. End-to-end tests go here. |
| [`tests/fixtures/sample_projects/python_rsa/crypto_utils.py`](tests/fixtures/sample_projects/python_rsa/crypto_utils.py) | Sample project: RSA key generation and signing using `cryptography` library. Used as a detection test target. |
| [`tests/fixtures/sample_projects/python_ecdh/key_exchange.py`](tests/fixtures/sample_projects/python_ecdh/key_exchange.py) | Sample project: ECDH key exchange using `cryptography` library. Used as a detection test target. |
| [`tests/fixtures/sample_projects/python_aes/encryption.py`](tests/fixtures/sample_projects/python_aes/encryption.py) | Sample project: AES-128 encryption. Used as a detection test target. |

### Bob sessions (screenshots)

| Directory | Purpose |
|---|---|
| [`bob_sessions/Maruti/`](bob_sessions/Maruti/) | Maruti's Bob session screenshots. Added on `changes-Maruti`, merged to `main`. |
| [`bob_sessions/Samik/`](bob_sessions/Samik/) | Samik's Bob session screenshots. Added on `changes-Samik`, merged to `main`. |
| [`bob_sessions/Navya/`](bob_sessions/Navya/) | Navya's Bob session screenshots. Added on `changes-Navya`, merged to `main`. |
| [`bob_sessions/Palak/`](bob_sessions/Palak/) | Palak's Bob session screenshots. Added on `changes-Palak`, merged to `main`. |

---

## Current pipeline architecture

The agreed end-to-end pipeline. All stages exist as empty stubs except CLI, models, and LLM client.

```
User
  │
  │  qsma scan <path>  /  qsma migrate <path>  /  qsma report  /  qsma validate
  ▼
┌──────────────────────────────────────────────────┐
│  CLI  (src/qsma/cli/main.py)                     │
│  Click group — thin entry point only             │
│  Delegates all logic to domain modules below     │
└───────────────────────┬──────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────┐
│  Ingestion  (src/qsma/ingestion/)                │
│  • Walks target directory (respects .gitignore)  │
│  • Reads source files, applies extension filter  │
│  • Produces: CodebaseSnapshot                    │
└───────────────────────┬──────────────────────────┘
                        │ CodebaseSnapshot
                        ▼
┌──────────────────────────────────────────────────┐
│  Analyzer  (src/qsma/analyzer/)                  │
│  • Parses each file with libcst (not ast module) │
│  • Extracts: imports, function calls, call graph │
│  • Tracks: ImportRef, CallSite, file→symbol map  │
│  • Produces: AnalyzedCodebase                    │
└───────────────────────┬──────────────────────────┘
                        │ AnalyzedCodebase
                        ▼
┌──────────────────────────────────────────────────┐
│  Detector  (src/qsma/detector/)                  │
│  • Pattern-matches known crypto library usage    │
│  • Distinguishes import from actual call site    │
│  • Uses rule definitions (pattern library)       │
│  • Produces: list[CryptoHit]  (raw, unclassified)│
└───────────────────────┬──────────────────────────┘
                        │ list[CryptoHit]
                        ▼
┌──────────────────────────────────────────────────┐
│  Classifier  (src/qsma/classifier/)              │
│  • Assigns QuantumRisk, severity_score, urgency  │
│  • Maps algorithm → NIST post-quantum guidance   │
│  • Deterministic — never calls LLM               │
│  • Produces: list[CryptoFinding]  (models.py)    │
└───────────────────────┬──────────────────────────┘
                        │ list[CryptoFinding]
                        ▼  (user selects findings to migrate)
┌──────────────────────────────────────────────────┐
│  Planner  (src/qsma/planner/)                    │
│  • Chooses migration strategy per finding        │
│  • Deterministic path: known rewrite rules       │
│  • LLM-assisted path: complex/unknown patterns   │
│  • Uses: LLMClient (watsonx.ai by default)       │
│  • Produces: MigrationPlan per selected finding  │
└───────────────────────┬──────────────────────────┘
                        │ MigrationPlan
                        ▼
┌──────────────────────────────────────────────────┐
│  Migrator  (src/qsma/migrator/)                  │
│  • Deterministic path: libcst AST transforms     │
│  • LLM-assisted path: prompt → code rewrite      │
│  • Updates parameters, key sizes, dependencies   │
│  • Produces: TransformationResult per finding    │
└───────────────────────┬──────────────────────────┘
                        │ TransformationResult
                        ▼
┌──────────────────────────────────────────────────┐
│  Validator  (src/qsma/validator/)                │
│  • Runs build/compile check where applicable     │
│  • Runs existing test suite if present           │
│  • Detects regressions vs. pre-migration baseline│
│  • Produces: ValidationResult                    │
└───────────────────────┬──────────────────────────┘
                        │ ValidationResult
                        ▼
┌──────────────────────────────────────────────────┐
│  Reporter  (src/qsma/reporter/)                  │
│  • Formats output: text / JSON / markdown        │
│  • Assembles ScanReport from all pipeline data   │
│  • Writes to stdout or --output file             │
└──────────────────────────────────────────────────┘

Shared infrastructure (used by Planner + Migrator only):
┌──────────────────────────────────────────────────┐
│  LLM Client  (src/qsma/llm/client.py)            │
│  • Provider-agnostic: watsonx / openai / anthropic│
│  • Switch via LLM_PROVIDER env var only          │
│  • Mock provider available for unit tests        │
└──────────────────────────────────────────────────┘

Inter-module data contracts (all defined in src/qsma/utils/models.py):
  CodeLocation · CryptoFinding · MigrationPlan
  TransformationResult · ValidationResult · ScanReport
  QuantumRisk · Algorithm · MigrationStatus  (enums)
```

**Key technology decisions:**
- **libcst** (not Python `ast`) for AST — preserves comments and formatting on roundtrip
- **IBM watsonx.ai** as default LLM (Granite Code model) — switch via `.env` only
- **Pydantic** for all inter-module data models — single file, single source of truth
- **Click + Rich** for CLI — thin layer, no business logic in CLI module
- **Stateless** — no database; optional JSON scan cache in `.qsma_cache/`

---

## Per-branch architecture state

**AI rule:** When you implement anything on your branch, update your row here in the same commit.  
Format: `feat(<module>): implement X — updates ARCHITECTURE.md branch state`

When merging into `main`: update the `main` row to include the newly merged module,
and update the branch row to `synced to main`.

| Branch | Phase | Ahead of main | Currently implementing | Notes |
|---|---|---|---|---|
| `main` | 0 | — | nothing (foundation complete) | CLI stub, models, LLM client, test fixtures |
| `changes-Maruti` | 0 | 2 commits | nothing yet | bob_sessions screenshot + PROMPT.md update |
| `changes-Samik` | 0 | synced | nothing yet | — |
| `changes-Navya` | 0 | synced | nothing yet | — |
| `changes-Palak` | 0 | synced | nothing yet | — |
