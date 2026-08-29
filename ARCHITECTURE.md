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
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | **Master source of truth.** 17 sections: product overview, architecture, every module spec, inter-module contracts, task DAG, parallelization plan, Git strategy, phases, testing strategy, tech decisions, ADR log, known risks, current status, next tasks. Read before any work. |
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
| [`src/qsma/cli/main.py`](src/qsma/cli/main.py) | ✅ Implemented | **CLI entry point.** Click group `cli` with 4 sub-commands: `scan(path, fmt, output)`, `report(path, findings)`, `migrate(path, finding_id, dry_run, auto, resume)`, `validate(path, timeout)`. All commands respond but delegate no logic yet — each prints a stub message. Uses `rich.console.Console` for output. |
| [`src/qsma/utils/__init__.py`](src/qsma/utils/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/utils/models.py`](src/qsma/utils/models.py) | ✅ Implemented | **Canonical inter-module contracts (Pydantic).** Do NOT redefine these in individual modules. Contains: `QuantumRisk` enum, `Algorithm` enum (including post-quantum targets), `MigrationStatus` enum, `CodeLocation`, `CryptoHit`, `CryptoFinding` (dual risk scores + blast_radius), `DependencyNode`, `DependencyGraph`, `MigrationPlan`, `TransformationResult`, `ValidationResult`, `ScanReport`. **To add:** `MigrationSessionState`, `AdvisorSession`. |
| [`src/qsma/utils/session.py`](src/qsma/utils/session.py) | 🔲 Stub | **Planned (Phase 2):** Redis session manager. Serialize/deserialize `MigrationSessionState`. `get_session(id)`, `save_session(state)`, `delete_session(id)`. Falls back to in-memory if Redis unavailable. |
| [`src/qsma/llm/__init__.py`](src/qsma/llm/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/llm/client.py`](src/qsma/llm/client.py) | ✅ Implemented | **Provider-agnostic LLM client.** Class `LLMClient`. Providers: `watsonx` (default), `openai_compatible`, `anthropic_compatible`, `mock`. Switch via `LLM_PROVIDER` env var. Called by LangGraph agent nodes — never called directly by pipeline modules. |
| [`src/qsma/llm/training_data/`](src/qsma/llm/training_data/) | 🔲 Stub | **Planned (Phase 2):** Few-shot migration examples (`few_shot/*.json`) and agent system prompts (`prompts/*.txt`). One JSON file per algorithm-family migration pair. Loaded at agent startup. See ADR-009. |
| [`src/qsma/agent/__init__.py`](src/qsma/agent/__init__.py) | 🔲 Stub | **Planned (Phase 2):** Package marker for LangGraph agent graph. |
| [`src/qsma/agent/graph.py`](src/qsma/agent/graph.py) | 🔲 Stub | **Planned (Phase 2):** LangGraph `StateGraph` wiring `planner_node → migrator_node → validator_node`. Conditional edges for retry (≤3) and escalation. Redis checkpointer via `RedisSaver`. See ADR-007. |
| [`src/qsma/ingestion/__init__.py`](src/qsma/ingestion/__init__.py) | 🔲 Stub | Empty. Planned: file walker, `CodebaseSnapshot`, `IngestionConfig`. Language detection by file extension. |
| [`src/qsma/analyzer/__init__.py`](src/qsma/analyzer/__init__.py) | 🔲 Stub | Empty. Planned: **tree-sitter** multi-language AST parser (all languages) + libcst CST builder (Python only). Produces `AnalysisResult` with `ParsedFile` per source file. See ADR-006. |
| [`src/qsma/detector/__init__.py`](src/qsma/detector/__init__.py) | 🔲 Stub | Empty. Planned: (A) tree-sitter query-based pattern matching → `list[CryptoHit]`; (B) build intra-codebase `DependencyGraph` and persist to Neo4j. See ADR-010. |
| [`src/qsma/classifier/__init__.py`](src/qsma/classifier/__init__.py) | 🔲 Stub | Empty. Planned: dual risk scoring — `algorithm_risk_score` (deterministic NIST table, no LLM) + `migration_risk_score` (LLM-assisted, uses `DependencyGraph.blast_radius`). Produces `list[CryptoFinding]`. See ADR-011. |
| [`src/qsma/advisor/__init__.py`](src/qsma/advisor/__init__.py) | 🔲 Stub | **NEW.** Planned (Phase 2): LLM-backed conversational REPL. Receives `list[CryptoFinding]` + `DependencyGraph`; user interacts in natural language; returns confirmed `list[finding_id]`. Entry point: `qsma chat`. See ADR-012. |
| [`src/qsma/planner/__init__.py`](src/qsma/planner/__init__.py) | 🔲 Stub | Empty. Planned: **LangGraph node** `planner_node(state)`. Always calls LLM: produces `MigrationPlan` (target algorithm, dependency changes, transformation hints) from `CryptoFinding` + few-shot examples. NIST target table is prompt context, not hard-coded rules. Persists to Redis. |
| [`src/qsma/migrator/__init__.py`](src/qsma/migrator/__init__.py) | 🔲 Stub | Empty. Planned: **LangGraph node** `migrator_node(state)`. Fully LLM-driven: builds prompt from `MigrationPlan` + code context + few-shot examples → calls `LLMClient` → splices result into source file via libcst patcher. Retries on Validator signal (max 3). Persists per-file result to Redis. |
| [`src/qsma/validator/__init__.py`](src/qsma/validator/__init__.py) | 🔲 Stub | Empty. Planned: **LangGraph node** `validator_node(state)`. Syntax check + test run + LLM failure analysis. Routes: pass → Reporter, retry → migrator_node, escalate → MANUAL_REQUIRED. |
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
  │  qsma scan <path>  /  qsma migrate <path> [--resume <id>]  /  qsma report  /  qsma validate
  ▼
┌──────────────────────────────────────────────────┐
│  CLI  (src/qsma/cli/main.py)                     │
│  Click group — thin entry point only             │
│  Delegates all logic to domain modules below     │
│  migrate: --resume <session_id> resumes from     │
│           Redis session state (ADR-008)          │
└───────────────────────┬──────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────┐
│  Ingestion  (src/qsma/ingestion/)                │
│  • Walks target directory (respects .gitignore)  │
│  • Reads source files, detects language by ext   │
│  • Produces: CodebaseSnapshot (SourceFile list)  │
└───────────────────────┬──────────────────────────┘
                        │ CodebaseSnapshot
                        ▼
┌──────────────────────────────────────────────────┐
│  Analyzer  (src/qsma/analyzer/)                  │
│  • PRIMARY: tree-sitter — all languages          │
│    Parses imports, call sites, identifiers       │
│  • SECONDARY: libcst — Python only               │
│    Builds cst_tree for lossless Migrator use     │
│  • Produces: AnalysisResult (ParsedFile list)    │
└───────────────────────┬──────────────────────────┘
                        │ AnalysisResult
                        ▼
┌──────────────────────────────────────────────────┐
│  Detector  (src/qsma/detector/)                  │
│  Phase A: tree-sitter query pattern matching     │
│  • Works across ALL supported languages          │
│  • Per-language crypto pattern libraries         │
│  • Tags each CryptoHit with dependency_node_id   │
│  Phase B: dependency graph construction          │
│  • Builds DependencyGraph (nodes + edges)        │
│  • Computes direct + transitive dependents       │
│  • Persists to Neo4j (optional; in-memory fallback)│
│  • Produces: list[CryptoHit] + DependencyGraph   │
└──────────┬──────────────────────────┬────────────┘
           │ list[CryptoHit]          │ DependencyGraph
           │                          │ (also → Neo4j)
           └──────────┬───────────────┘
                      ▼
┌──────────────────────────────────────────────────┐
│  Classifier  (src/qsma/classifier/)              │
│  Score 1 — algorithm_risk_score (deterministic): │
│  • Hard-coded NIST risk table; never calls LLM   │
│  • RSA/ECC/DH=10.0, AES-128=7.0, AES-256=2.0…  │
│  Score 2 — migration_risk_score (LLM-assisted):  │
│  • blast_radius from DependencyGraph             │
│  • usage_type + library coupling + complexity    │
│  • LLM optional; heuristic fallback available    │
│  severity_score = 0.6×alg_risk + 0.4×mig_risk  │
│  • Produces: list[CryptoFinding]  (models.py)    │
└───────────────────────┬──────────────────────────┘
                        │ list[CryptoFinding]
                        ▼  (user selects findings to migrate)
┌─────────────────────────────────────────────────────────────┐
│  LangGraph MigrationGraph  (src/qsma/agent/graph.py)        │
│  StateGraph backed by Redis checkpointer (RedisSaver)       │
│  State: MigrationSessionState (Pydantic, persisted to Redis)│
│                                                             │
│  ┌────────────────────────────────────────────────────┐     │
│  │  planner_node  (src/qsma/planner/)                 │     │
│  │  • LLM agent: reasons migration strategy per       │     │
│  │    finding; NIST targets are prompt context        │     │
│  │  • Loads training_data/few_shot/*.json             │     │
│  │  • Produces: MigrationPlan, persists to Redis      │     │
│  └──────────────────────────┬─────────────────────────┘     │
│                             │ MigrationPlan                  │
│                             ▼                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │  migrator_node  (src/qsma/migrator/)               │     │
│  │  • LLM agent: generates transformed code snippet   │     │
│  │  • libcst patcher splices snippet into source file │     │
│  │  • Persists TransformationResult to Redis          │     │
│  └──────────────────────────┬─────────────────────────┘     │
│                             │ TransformationResult           │
│                             ▼                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │  validator_node  (src/qsma/validator/)             │     │
│  │  • Syntax check (ast.parse / tree-sitter)          │     │
│  │  • Dependency check + test run                     │     │
│  │  • LLM failure analysis → retry_hints              │     │
│  │  • Routes: pass → Reporter                         │     │
│  │            retry (attempt<3) → migrator_node       │     │
│  │            escalate → MANUAL_REQUIRED              │     │
│  └──────────────────────────┬─────────────────────────┘     │
└─────────────────────────────┼───────────────────────────────┘
                              │ ValidationResult
                              ▼
┌──────────────────────────────────────────────────┐
│  Reporter  (src/qsma/reporter/)                  │
│  • Formats output: text / JSON / markdown        │
│  • Assembles ScanReport from all pipeline data   │
│  • Writes to stdout or --output file             │
└──────────────────────────────────────────────────┘

Shared infrastructure:
┌──────────────────────────────────────────────────┐
│  LLM Client  (src/qsma/llm/client.py)            │
│  • Provider-agnostic: watsonx / openai / anthropic│
│  • Called by LangGraph agent nodes only          │
│  • Mock provider available for unit tests        │
└──────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────┐
│  Session Manager  (src/qsma/utils/session.py)    │
│  • Redis read/write for MigrationSessionState    │
│  • TTL: 24h (REDIS_SESSION_TTL_SECONDS in .env)  │
│  • Fallback: in-memory if Redis unavailable      │
└──────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────┐
│  Agent Training Data                             │
│  (src/qsma/llm/training_data/)                   │
│  • few_shot/*.json — per-algorithm few-shot pairs│
│  • prompts/*.txt   — agent system prompts        │
│  • Loaded at agent startup; version-controlled   │
└──────────────────────────────────────────────────┘

Inter-module data contracts (all defined in src/qsma/utils/models.py):
  CodeLocation · CryptoHit · CryptoFinding · MigrationPlan
  DependencyNode · DependencyGraph (blast_radius method)
  TransformationResult · ValidationResult · ScanReport
  MigrationSessionState (LangGraph state — includes session_id, pending_plans,
    completed_findings, retry_count, retry_hints)
  QuantumRisk · Algorithm · MigrationStatus  (enums)
```

**Key technology decisions:**
- **tree-sitter** (primary parser) for multi-language AST in Analyzer + Detector — 40+ languages, single query API
- **libcst** (Python-only, Migrator only) for lossless CST roundtrip — preserves comments and formatting
- **LangGraph ≥ 0.2** for agentic Planner → Migrator → Validator loop with typed state and retry
- **Redis** for session state persistence — mid-run resume via `--resume <session_id>`
- **Neo4j** for intra-codebase dependency graph — `IMPORTS_FROM`/`CALLS` edges; blast-radius queries by Classifier + Planner (optional; in-memory fallback) — see ADR-010
- **IBM watsonx.ai** as default LLM (Granite Code model) — switch via `.env` only
- **Pydantic v2** for all inter-module data models including `MigrationSessionState`, `DependencyGraph`, `CryptoHit`
- **Click + Rich** for CLI — thin layer, no business logic in CLI module

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
