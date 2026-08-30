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

**Phase:** 2 — Migration pipeline working end-to-end
**Last updated:** 2026-08-30
**What is implemented:** The full pipeline is real and wired end-to-end:
Ingestion → Analyzer → Detector → Classifier → CLI, and the LangGraph
`agent/graph.py` orchestrating Planner → Migrator → Validator with retry/
escalation. Verified against real open-source codebases (PyJWT, python-jose)
with a real LLM (not mock) — see `bob_sessions/` and the demo steps in
`README.md`. Multilingual detection covers Python, Java, Go, C, and Rust.
**What is NOT yet implemented:** the Advisor module (`qsma chat` is a
placeholder — natural-language finding selection is out of scope for this
submission; use `--finding-id`/`--auto` instead, see "Selecting findings to
migrate" below), and Redis-backed session persistence (an in-memory session
store is used instead — same function signatures, same `--resume` UX within
a single process; swapping in real Redis is a drop-in change).

### Selecting findings to migrate

`qsma scan` (via the Classifier) produces `list[CryptoFinding]`, each with a
stable `id` (e.g. `QSMA-0009`). `qsma migrate` selects which of those to act
on via:
- `--finding-id ID [--finding-id ID ...]` — migrate specific findings only
- `--auto` — auto-select every `CRITICAL`/`HIGH` finding
- neither flag — no findings selected, command exits cleanly with a hint

This is the real, working selection mechanism today. The Advisor's
natural-language selection (`qsma chat`) is a stretch goal on top of this,
not a replacement for it.

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
| [`src/qsma/cli/main.py`](src/qsma/cli/main.py) | ✅ Implemented | **CLI entry point.** Click group `cli` with 5 sub-commands: `scan(path, fmt, output)`, `report(path, findings, fmt)`, `migrate(path, finding_id, dry_run, auto, resume)`, `validate(path, timeout)`, `chat(...)` (placeholder). `scan`/`report`/`migrate`/`validate` call the real pipeline (Ingestion→Analyzer→Detector→Classifier→Reporter, and Agent for migrate/validate) — no mocked data. Uses `rich.console.Console`/`rich.table.Table` for output. |
| [`src/qsma/utils/__init__.py`](src/qsma/utils/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/utils/models.py`](src/qsma/utils/models.py) | ✅ Implemented | **Canonical inter-module contracts (Pydantic).** Do NOT redefine these in individual modules. Contains: `QuantumRisk` enum, `Algorithm` enum (including post-quantum targets), `MigrationStatus` enum, `CodeLocation` (incl. `snippet` — the actual source text for a finding, populated by the Classifier), `CryptoHit`, `CryptoFinding` (dual risk scores + blast_radius), `DependencyNode`, `DependencyGraph`, `MigrationPlan`, `TransformationResult`, `ValidationResult`, `ScanReport`, `MigrationExecutionPlan`, `FindingMeta`, `MigrationSessionState`. |
| [`src/qsma/utils/session.py`](src/qsma/utils/session.py) | ⚠️ In-memory | `get_session(id)`/`save_session(state)`/`delete_session(id)` against a module-level `dict`. Same signatures as the planned Redis design — swapping in `RedisSaver` later is a drop-in change, not a rewrite. `--resume` works within a single process only. |
| [`src/qsma/llm/__init__.py`](src/qsma/llm/__init__.py) | Stub | Package marker. Empty. |
| [`src/qsma/llm/client.py`](src/qsma/llm/client.py) | ✅ Implemented | **Provider-agnostic LLM client.** Class `LLMClient`. Providers: `watsonx` (default), `openai_compatible` (verified against real Groq — `openai/gpt-oss-120b`), `anthropic_compatible`, `mock`. Switch via `LLM_PROVIDER` env var. Called by Planner/Migrator/Validator nodes. |
| [`src/qsma/llm/training_data/`](src/qsma/llm/training_data/) | ✅ Implemented | Few-shot migration examples (`few_shot/*.json` — RSA→ML-DSA, ECDSA→ML-DSA, ECDH→ML-KEM, AES-128→AES-256, MD5/SHA-1→SHA-256) and agent system prompts (`prompts/*.txt`). Loaded by Planner/Migrator via `_load_few_shot`. |
| [`src/qsma/agent/__init__.py`](src/qsma/agent/__init__.py) | ✅ Implemented | Exports `build_graph`, `run_migration_session` from `graph.py`. |
| [`src/qsma/agent/graph.py`](src/qsma/agent/graph.py) | ✅ Implemented | Real LangGraph `StateGraph` over `MigrationSessionState`: `planner`→`migrator`⇄`validator` (retry ≤3, escalate on failure) →`advance` to the next finding → `END`. In-memory checkpointer (no Redis — see above). Verified end-to-end with a real LLM against real open-source code. |
| [`src/qsma/ingestion/__init__.py`](src/qsma/ingestion/__init__.py) | ✅ Implemented | Exports `collect_snapshot` from `walker.py`. |
| [`src/qsma/ingestion/walker.py`](src/qsma/ingestion/walker.py) | ✅ Implemented | `collect_snapshot(path, config)` — recursive walk, `.gitignore`-aware (via `pathspec`), configurable exclude patterns/extensions, binary/size filtering, deterministic ordering → `CodebaseSnapshot`. |
| [`src/qsma/analyzer/__init__.py`](src/qsma/analyzer/__init__.py) | ✅ Implemented | Exports `analyse_snapshot`, `parse_file` from `parser.py`. |
| [`src/qsma/analyzer/parser.py`](src/qsma/analyzer/parser.py) | ✅ Implemented | tree-sitter (Python/Java/Go/C/Rust) + libcst (Python only). Real structural extraction (imports/functions/classes/calls) for **all 5 languages** — includes Java's `getInstance("ALGO")` factory-call argument capture and Go/Rust qualified-receiver call capture, needed to disambiguate JCA-style APIs. |
| [`src/qsma/analyzer/languages.py`](src/qsma/analyzer/languages.py) | ✅ Implemented | tree-sitter `Language`/`Parser` singletons per language. |
| [`src/qsma/analyzer/crypto_imports.py`](src/qsma/analyzer/crypto_imports.py) | ✅ Implemented | Per-language crypto-import allowlists (Python/Java/Go/C/Rust) — `is_crypto_import(module, language)`. |
| [`src/qsma/detector/__init__.py`](src/qsma/detector/__init__.py) | ✅ Implemented | `detect(analysis, session_id, root_path)` → Phase A (`run_detection`) + Phase B (`build_dependency_graph`). |
| [`src/qsma/detector/patterns/{rsa,ecc,symmetric,hashing}.py`](src/qsma/detector/patterns/) | ✅ Implemented | Per-algorithm `DetectionRule`s. Each file has both the original Python-specific rules and a `_match_<algo>_multilang` rule covering Java/Go/C/Rust (RSA/ECC key-gen/sign/exchange, AES/DES encryption, MD5/SHA-1/SHA-256 hashing). |
| [`src/qsma/detector/graph.py`](src/qsma/detector/graph.py) | ✅ Implemented | `build_dependency_graph` — per-file `DependencyNode`s, direct/transitive dependents via BFS, `has_crypto` tagging, optional Neo4j persistence (in-memory always works). |
| [`src/qsma/classifier/__init__.py`](src/qsma/classifier/__init__.py) | ✅ Implemented | `classify(hits, graph, llm=None)` → `list[CryptoFinding]`. `ALGORITHM_RISK_TABLE` (deterministic, no LLM) + heuristic/LLM-assisted `migration_risk_score` (blast_radius + usage_type weighted; heuristic is always the fallback). Also reads the real source snippet for each finding's `CodeLocation.snippet` — the only place in the pipeline that does, which Planner/Migrator both depend on. |
| [`src/qsma/advisor/__init__.py`](src/qsma/advisor/__init__.py) | 🔲 Stub — deferred | Out of scope for this submission (see "Current state on `main`" above). `qsma chat` remains a placeholder. |
| [`src/qsma/planner/__init__.py`](src/qsma/planner/__init__.py) | ✅ Implemented | `planner_node(state)` — LLM call per finding → `MigrationPlan`, topo-sorted + wave-packed into `MigrationExecutionPlan`. `_NIST_TARGETS` covers RSA/ECDSA/DSA/DH/ECDH/AES-128/DES/3DES/MD5/SHA-1. |
| [`src/qsma/migrator/__init__.py`](src/qsma/migrator/__init__.py) | ✅ Implemented | `migrator_node(state)` — LLM transform via `llm_transform.py`, patched into the source file via `patcher.py`. Builds `ValidatorState` for the Validator (`build_validator_state`). |
| [`src/qsma/migrator/llm_transform.py`](src/qsma/migrator/llm_transform.py) | ✅ Implemented | Prompt builder + response parser. Re-indents the LLM's reply to match the original snippet's indentation (single-line originals are flattened to one level; multi-line originals keep the model's relative nesting) — Python is indentation-sensitive and the model reliably dedents "return only the code" replies. |
| [`src/qsma/migrator/patcher.py`](src/qsma/migrator/patcher.py) | ✅ Implemented | libcst-based line-range splice, atomic write, dry-run diff mode, syntax-validates the patched result before writing. |
| [`src/qsma/validator/node.py`](src/qsma/validator/node.py) | ✅ Implemented | `validator_node(state)` — syntax check (`ast.parse`) + `pytest` run + LLM-generated retry hints on failure. Routes pass/retry/escalate via the returned dict's `retry_hints`/`validation_results`. |
| [`src/qsma/reporter/__init__.py`](src/qsma/reporter/__init__.py) | ✅ Implemented | `build_scan_report`, `finding_rows`, `format_text`/`format_json`/`format_markdown`. Owns all findings sorting/aggregation — CLI only renders. |

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
| [`tests/fixtures/sample_projects/python_aes_ecb/aes_ecb.py`](tests/fixtures/sample_projects/python_aes_ecb/aes_ecb.py) | Sample project: AES in ECB mode. |
| [`tests/fixtures/sample_projects/python_hashing/hash_utils.py`](tests/fixtures/sample_projects/python_hashing/hash_utils.py) | Sample project: MD5/SHA-1 hashing. |
| [`tests/unit/test_classifier.py`](tests/unit/test_classifier.py) | Classifier: risk table, severity formula, QuantumRisk bucketing, heuristic/LLM migration-risk scoring, `classify()` end-to-end. |
| [`tests/unit/test_reporter.py`](tests/unit/test_reporter.py) | Reporter: `build_scan_report` aggregation/sorting, all three output formats, JSON round-trip. |
| [`tests/unit/test_agent_graph.py`](tests/unit/test_agent_graph.py) | Agent: happy path, escalation on an invalid transform, no-findings, multi-finding processing — all via `LLMClient(provider="mock")`. |
| [`tests/unit/test_llm_transform.py`](tests/unit/test_llm_transform.py) | Migrator: the reindent-to-match logic (single-line flatten vs. multi-line relative nesting), added after a real end-to-end test against PyJWT surfaced the indentation bug. |
| [`tests/unit/test_detector_multilang.py`](tests/unit/test_detector_multilang.py) | Detector: RSA/AES/hashing detection for Java, Go, C, and Rust synthetic snippets. |
| [`tests/unit/test_cli.py`](tests/unit/test_cli.py) | CLI: `scan`/`report`/`migrate`/`validate` against a real fixture via Click's `CliRunner`, `LLM_PROVIDER=mock`. |

**196/196 tests pass** (`pytest tests/ -q`). Also verified against **real open-source
codebases with a real LLM** (not a fixture, not mocked): PyJWT (RSA→ML-DSA) and
python-jose (SHA-1→SHA-256, validated clean against python-jose's own 458-test suite).

### Bob sessions (screenshots)

| Directory | Purpose |
|---|---|
| [`bob_sessions/Maruti/`](bob_sessions/Maruti/) | Maruti's Bob session screenshots. Added on `changes-Maruti`, merged to `main`. |
| [`bob_sessions/Samik/`](bob_sessions/Samik/) | Samik's Bob session screenshots. Added on `changes-Samik`, merged to `main`. |
| [`bob_sessions/Navya/`](bob_sessions/Navya/) | Navya's Bob session screenshots. Added on `changes-Navya`, merged to `main`. |
| [`bob_sessions/Palak/`](bob_sessions/Palak/) | Palak's Bob session screenshots. Added on `changes-Palak`, merged to `main`. |

---

## Current pipeline architecture

The agreed end-to-end pipeline — now real and working end-to-end (Advisor and
Redis are the two exceptions; see "Current state on `main`" above).

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
- **Redis** for session state persistence — mid-run resume via `--resume <session_id>` (planned; an in-memory store with the same interface is used today — see `utils/session.py` above)
- **Neo4j** for intra-codebase dependency graph — `IMPORTS_FROM`/`CALLS` edges; blast-radius queries by Classifier + Planner (optional — in-memory dependency graph is what's actually used; Neo4j persistence is a no-op unless `NEO4J_URI` is set) — see ADR-010
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
| `main` | 2 | — | — | Full pipeline real end-to-end: Ingestion, Analyzer, Detector (incl. multilingual), Classifier, Reporter, Agent (LangGraph), CLI wiring. See file index above. |
| `changes-Maruti` | 2 | synced | — | planner/migrator (original work) now merged to `main`, plus this session's Classifier, Reporter, Agent, CLI wiring, multilingual Detector rules, and the reindent/snippet/few-shot fixes found via real end-to-end testing. |
| `changes-Samik` | 2 | synced | — | Ingestion (`walker.py`), Analyzer (`parser.py`, tree-sitter multi-language), Detector (`patterns/`, `graph.py`) — merged to `main` via `401f054`. |
| `changes-Navya` | 0 | synced | nothing yet | — |
| `changes-Palak` | 0 | synced | nothing yet | CLI scaffold and Validator (`validator/node.py`) — merged to `main` prior to this session. |

**Not yet synced to `main` as of this update:** `changes-Navya`, `changes-Palak` local
branches may be behind — run `git merge main` on each before further work (see the
git commands used to bring `main` up to date after this session's changes).
