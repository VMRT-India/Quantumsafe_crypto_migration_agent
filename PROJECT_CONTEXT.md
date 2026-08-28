# PROJECT_CONTEXT.md
## Quantum-Safe Crypto Migration Agent — Master Project Context

> **CANONICAL SOURCE OF TRUTH**
> Every developer and every future AI session MUST read this document before starting work.
> Do NOT redesign components without updating this document first.
> Do NOT duplicate functionality described here.
> When a significant architectural change is necessary, record it in §15 (ADR Log) before implementing it.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Product Scope](#3-product-scope)
4. [System Architecture](#4-system-architecture)
5. [Module Catalogue](#5-module-catalogue)
6. [Module Specifications](#6-module-specifications)
7. [Inter-Module Contracts](#7-inter-module-contracts)
8. [Dependency Graph (DAG)](#8-dependency-graph-dag)
9. [Parallelization Plan](#9-parallelization-plan)
10. [Four-Person Work Allocation](#10-four-person-work-allocation)
11. [Git Branching Strategy](#11-git-branching-strategy)
12. [Development Phases](#12-development-phases)
13. [Testing Strategy](#13-testing-strategy)
14. [Technology Decisions](#14-technology-decisions)
15. [Architectural Decision Log (ADR)](#15-architectural-decision-log-adr)
16. [Known Risks](#16-known-risks)
17. [Current Status](#17-current-status)
18. [Next Tasks](#18-next-tasks)

---

## 1. Project Overview

**Product:** Quantum-Safe Crypto Migration Agent (`qsma`)
**Event:** IBM Dev Day Hackathon
**Team:** 4 developers
**Type:** CLI developer tool — no web frontend

### What we are building

A command-line tool that takes an existing software codebase, identifies cryptographic
operations that are vulnerable to quantum computers, explains the risk, and — for selected
findings — automatically rewrites the relevant code to use post-quantum alternatives, then
validates that the migration did not break the application.

### End-to-end workflow

```
qsma scan <path>      →  Analyse codebase, detect crypto, classify risk, display findings
qsma report <path>    →  Format and display / export a structured findings report
qsma migrate <path>   →  Interactively select findings and apply automated migration
qsma validate <path>  →  Post-migration: build, test, and report regression status
```

---

## 2. Problem Statement

Cryptographic algorithms are embedded throughout codebases, often written years ago.
Many are secure today against classical computers but will be broken by sufficiently capable
quantum computers (via Shor's algorithm for public-key crypto; Grover's algorithm weakens
symmetric key strengths).

Organizations must:
- Discover all cryptographic usage across their codebase
- Understand which algorithms are used and their quantum risk
- Prioritize what to change (not all crypto is equally urgent)
- Migrate vulnerable code to NIST-standardized post-quantum alternatives
- Verify that migrated code still works correctly

Manual migration is error-prone because crypto operations are coupled to:
key sizes, parameters, serialization formats, dependent data structures, APIs, and
downstream consumers.

**Key value proposition:** Take a developer from "I have a codebase" to "my critical
cryptography has been migrated and validated" in a single automated workflow.

---

## 3. Product Scope

### In scope (MVP — Hackathon)

| Area | Detail |
|---|---|
| Language support | Python (primary target) |
| Detection | RSA, ECDSA, ECDH, DSA, DH, AES-128, DES, 3DES, MD5, SHA-1 |
| Libraries detected | `cryptography`, `pycryptodome`, `hashlib`, `hmac`, `ssl`, `paramiko` |
| Risk classification | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| Migration targets | ML-KEM (Kyber), ML-DSA (Dilithium), AES-256, SHA-256+ |
| Migration method | Deterministic AST rewrites (primary) + LLM-assisted (fallback/complex cases) |
| Validation | Syntax check, optional `pytest` execution, optional `pip install` check |
| CLI interface | `scan`, `report`, `migrate`, `validate` commands |
| IBM technology | watsonx.ai (Granite Code model) for LLM-assisted migration |
| Output formats | terminal (rich), JSON, Markdown |

### Explicitly out of scope (MVP)

- Web UI / dashboard
- Multi-language support beyond Python (Java, Go, C++ — architecture allows extension)
- IDE plugins
- CI/CD pipeline integration (design for it, but don't implement)
- Automatic key rotation / secrets management
- Runtime / dynamic analysis
- Full library API compatibility guarantees across all versions

---

## 4. System Architecture

### Pipeline architecture (linear with fan-out at migration)

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI Layer                              │
│   qsma scan | qsma report | qsma migrate | qsma validate        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────▼──────────────┐
            │       Ingestion Module       │  Walk filesystem, parse files,
            │       (src/qsma/ingestion)   │  build CodebaseSnapshot
            └───────────────┬──────────────┘
                            │ CodebaseSnapshot
            ┌───────────────▼──────────────┐
            │       Analyzer Module        │  Build AST + call graph,
            │       (src/qsma/analyzer)    │  extract import/call sites
            └───────────────┬──────────────┘
                            │ AnalysisResult
            ┌───────────────▼──────────────┐
            │       Detector Module        │  Pattern-match crypto usage,
            │       (src/qsma/detector)    │  produce raw CryptoHits
            └───────────────┬──────────────┘
                            │ list[CryptoHit]
            ┌───────────────▼──────────────┐
            │      Classifier Module       │  Assign Algorithm, QuantumRisk,
            │      (src/qsma/classifier)   │  severity, recommendation
            └───────────────┬──────────────┘
                            │ list[CryptoFinding]
            ┌───────────────▼──────────────┐
            │       Reporter Module        │  Format and display findings
            │       (src/qsma/reporter)    │  (terminal / JSON / Markdown)
            └───────────────┬──────────────┘
                            │ (user selects findings interactively)
            ┌───────────────▼──────────────┐
            │       Planner Module         │  For each selected finding,
            │       (src/qsma/planner)     │  produce MigrationPlan
            └───────────────┬──────────────┘
                            │ list[MigrationPlan]
            ┌───────────────▼──────────────┐
            │      Migrator Module         │  Apply transformations;
            │      (src/qsma/migrator)     │  deterministic AST + LLM fallback
            └───────────────┬──────────────┘
                            │ list[TransformationResult]
            ┌───────────────▼──────────────┐
            │      Validator Module        │  Syntax check, build, test run
            │      (src/qsma/validator)    │  produce ValidationResult
            └───────────────┬──────────────┘
                            │ ValidationResult
            ┌───────────────▼──────────────┐
            │       Reporter Module        │  Final migration report
            │   (reused for final report)  │
            └──────────────────────────────┘
```

### LLM integration point

The LLM (watsonx.ai / Granite Code) is used **only** in:
1. **Planner** — generating migration strategies for complex/unknown patterns
2. **Migrator** — LLM-assisted transformation when deterministic rules are insufficient
3. **Classifier** — optional enrichment of explanation text (can be disabled)

The LLM is **not** used for detection or risk classification — these are deterministic.

### Shared utilities

`src/qsma/utils/models.py` — Pydantic data models (the shared contract layer)
`src/qsma/llm/` — watsonx.ai client wrapper, prompt templates, response parsing

---

## 5. Module Catalogue

| Module | Package | Responsibility |
|---|---|---|
| CLI | `qsma.cli` | Command routing, user interaction, progress display |
| Ingestion | `qsma.ingestion` | Filesystem walk, file filtering, raw source collection |
| Analyzer | `qsma.analyzer` | AST parsing, call graph, import resolution |
| Detector | `qsma.detector` | Pattern matching on AST nodes to find crypto usage |
| Classifier | `qsma.classifier` | Risk scoring, algorithm identification, recommendation |
| Planner | `qsma.planner` | Migration strategy selection per finding |
| Migrator | `qsma.migrator` | Code transformation (AST rewrite + LLM fallback) |
| Validator | `qsma.validator` | Post-migration build/test validation |
| Reporter | `qsma.reporter` | Output formatting (terminal, JSON, Markdown) |
| LLM Client | `qsma.llm` | watsonx.ai SDK wrapper, prompt templates |
| Models | `qsma.utils.models` | Shared Pydantic data-models (contracts) |

---

## 6. Module Specifications

---

### 6.1 Ingestion (`qsma.ingestion`)

**Purpose:** Walk the target codebase and collect source files for analysis.

**Inputs:** `target_path: Path`, optional `IngestionConfig`
**Outputs:** `CodebaseSnapshot` — list of `SourceFile` objects with path + raw content

**Responsibilities:**
- Recursive directory walk respecting `.gitignore` / configurable excludes
- File type filtering (`.py` for MVP; architecture allows extension)
- Large file / binary file exclusion
- Produce a reproducible, ordered snapshot

**Key classes:**
```
IngestionConfig    — exclude patterns, file extensions, max_file_size
SourceFile         — path, content, language
CodebaseSnapshot   — list[SourceFile], root_path, file_count
```

**Not responsible for:** Parsing, AST, any analysis.

**Can start immediately:** Yes — no upstream module dependencies.

---

### 6.2 Analyzer (`qsma.analyzer`)

**Purpose:** Parse source files into ASTs and extract structural information.

**Inputs:** `CodebaseSnapshot`
**Outputs:** `AnalysisResult` — per-file AST + import map + call sites

**Responsibilities:**
- Parse each `SourceFile` using `libcst` (Python MVP)
- Extract: imports, function definitions, class definitions, call expressions
- Build a lightweight intra-file call graph
- Identify which imports are cryptographic in origin (using an import allowlist)

**Key classes:**
```
ParsedFile     — path, cst_tree, imports, call_sites
ImportRef      — module, alias, line
CallSite       — function_name, arguments, line, enclosing_function
AnalysisResult — list[ParsedFile], import_index
```

**Not responsible for:** Risk scoring, pattern matching beyond structural extraction.

**Depends on:** Ingestion (CodebaseSnapshot)

---

### 6.3 Detector (`qsma.detector`)

**Purpose:** Identify concrete cryptographic usage sites from the analysis result.

**Inputs:** `AnalysisResult`
**Outputs:** `list[CryptoHit]`

**Responsibilities:**
- Apply a rule-based pattern library against AST nodes
- Distinguish: importing a crypto library vs. actually invoking a crypto operation
- Extract: algorithm, key_size (where present), usage_type, code location

**Detection strategy:**
- Pattern library: `src/qsma/detector/patterns/` — one file per algorithm family
- Each pattern is a `DetectionRule` with: name, AST matcher, algorithm hint, usage_type

**Key classes:**
```
DetectionRule  — rule_id, algorithm_hint, usage_type, matcher_fn
CryptoHit      — rule_id, algorithm_hint, usage_type, location, raw_node_info
```

**Not responsible for:** Risk scoring — that is the Classifier's job.

**Depends on:** Analyzer (AnalysisResult)

---

### 6.4 Classifier (`qsma.classifier`)

**Purpose:** Assign quantum risk, severity, explanation, and recommendation to each hit.

**Inputs:** `list[CryptoHit]`
**Outputs:** `list[CryptoFinding]`

**Responsibilities:**
- Map detected algorithms to `QuantumRisk` level using a risk table
- Assign `severity_score` (0–10)
- Generate human-readable `explanation` (deterministic template + optional LLM enrichment)
- Generate `recommendation` (deterministic — points to NIST PQC alternative)

**Risk table (deterministic — do not change without ADR):**
| Algorithm | Risk | Reason |
|---|---|---|
| RSA (any key size) | CRITICAL | Shor's algorithm breaks integer factoring |
| ECDSA, ECDH, DSA, DH | CRITICAL | Shor's algorithm breaks discrete log |
| AES-128 | HIGH | Grover halves effective key strength to ~64 bits |
| DES, 3DES | CRITICAL | Classically weak + quantum-reduced further |
| MD5, SHA-1 | HIGH | Collision-broken classically; further weakened |
| AES-256 | LOW | Grover reduces to ~128-bit — still acceptable |
| SHA-256, SHA-384, SHA-512 | LOW | Grover reduces by half — remains adequate |

**Depends on:** Detector (list[CryptoHit])

---

### 6.5 Planner (`qsma.planner`)

**Purpose:** For each selected CryptoFinding, produce an actionable MigrationPlan.

**Inputs:** `list[CryptoFinding]` (selected subset)
**Outputs:** `list[MigrationPlan]`

**Responsibilities:**
- Select migration strategy: deterministic_rewrite | llm_assisted | manual_only
- Identify target algorithm (NIST PQC standard)
- Determine if dependency changes are needed (`requirements.txt` additions)
- Generate `transformation_hints` for the Migrator

**Strategy selection logic:**
```
RSA sign/verify  → deterministic → ML-DSA (Dilithium)
ECDSA sign/verify → deterministic → ML-DSA (Dilithium)
ECDH key exchange → deterministic → ML-KEM (Kyber)
AES-128 encrypt  → deterministic → AES-256 (key size increase)
DES / 3DES       → deterministic → AES-256
Unknown patterns → llm_assisted
```

**LLM use:** Called when strategy == `llm_assisted` to produce structured transformation hints.

**Depends on:** Classifier output (list[CryptoFinding]), LLM Client (optional)

---

### 6.6 Migrator (`qsma.migrator`)

**Purpose:** Apply the MigrationPlan to source files and produce modified code.

**Inputs:** `list[MigrationPlan]`, `CodebaseSnapshot` (for file content access)
**Outputs:** `list[TransformationResult]`

**Responsibilities:**
- **Deterministic path:** Apply libcst-based CST transformations for known patterns
  - Preserves formatting, comments, and surrounding code
  - One `Transformer` class per algorithm-family migration
- **LLM-assisted path:** For complex/unknown patterns, send context + plan to LLM,
  parse the response, apply the proposed diff with validation
- Write transformed files (dry-run mode: only produce diffs, no file writes)
- Record what changed per finding

**Sub-modules:**
```
migrator/transformers/  — one .py file per deterministic transformation rule
migrator/llm_transform.py — LLM-assisted transformation handler
migrator/patcher.py     — safely applies transformations to files
```

**Safety invariants:**
- A transformation MUST NOT modify code outside the identified finding's scope
- All file modifications are atomic (write to temp → move on success)
- Dry-run mode must produce identical output as real run, minus file writes

**Depends on:** Planner (MigrationPlan), Ingestion (CodebaseSnapshot), LLM Client

---

### 6.7 Validator (`qsma.validator`)

**Purpose:** Verify post-migration correctness of the codebase.

**Inputs:** `list[TransformationResult]`, `target_path: Path`
**Outputs:** `ValidationResult`

**Validation steps (in order):**
1. **Syntax check** — parse all modified files with `ast.parse` (fast, always runs)
2. **Dependency check** — if new packages required, attempt `pip install --dry-run`
3. **Test execution** — if `pytest` / `unittest` tests exist, run them with timeout
4. **Regression detection** — compare test results before/after migration

**Not responsible for:** Functional correctness of the cryptographic replacement.
That is guaranteed by the deterministic rules in the Migrator.

**Depends on:** Migrator (TransformationResult), filesystem (for test execution)

---

### 6.8 Reporter (`qsma.reporter`)

**Purpose:** Format and render findings and migration results for the CLI user.

**Inputs:** `list[CryptoFinding]` or `ScanReport`
**Outputs:** Rendered output (stdout via `rich`, JSON file, Markdown file)

**Responsibilities:**
- Terminal table / summary using `rich`
- JSON export (structured `ScanReport`)
- Markdown report (human-readable, for submission / documentation)
- Per-finding detail view
- Summary statistics (counts by risk level)

**Depends on:** Classifier (CryptoFinding), Validator (ValidationResult) for final report

---

### 6.9 LLM Client (`qsma.llm`)

**Purpose:** Centralized wrapper for watsonx.ai / Granite Code model calls.

**Responsibilities:**
- Load credentials from environment (never hardcoded)
- Provide typed `generate(prompt, params) → str` interface
- Manage prompt templates (stored in `qsma/llm/prompts/`)
- Handle retry, timeout, and error normalization
- Allow mocking in tests via dependency injection

**Key design:** All other modules call `LLMClient.generate()` — never call the SDK directly.
This isolates the IBM dependency and makes it replaceable/mockable.

**Depends on:** `.env` / environment variables; `ibm-watsonx-ai` SDK

---

## 7. Inter-Module Contracts

All data models are defined in `src/qsma/utils/models.py`.
**Do not redefine these structures in individual modules.**

### Critical contracts

```
CodebaseSnapshot  →  [Ingestion produces]  →  Analyzer consumes
AnalysisResult    →  [Analyzer produces]   →  Detector consumes
list[CryptoHit]   →  [Detector produces]   →  Classifier consumes
list[CryptoFinding] → [Classifier produces] → Planner, Reporter consume
list[MigrationPlan] → [Planner produces]   → Migrator consumes
list[TransformationResult] → [Migrator produces] → Validator, Reporter consume
ValidationResult  →  [Validator produces]  →  Reporter consumes
```

Detailed JSON schemas for each are in `docs/contracts/`.

---

## 8. Dependency Graph (DAG)

> **This DAG is a living document, not a permanent fixture.**
> As implementation reveals better module boundaries, task splits, or merges,
> update this section and record any architectural change in §15 (ADR Log).
> Task IDs (T-01 … T-19) are stable references — if you renumber them, update
> every reference in §9, §10, and §12 in the same commit.

```
[Models/Utils]  ←  all modules depend on this (no dependencies itself)
     │
     ▼
[LLM Client]    ←  no module dependencies (only env vars + OpenAI-compatible SDK)
     │
[Ingestion]     ←  no module dependencies
     │
     ▼
[Analyzer]      ←  depends on: Ingestion
     │
     ▼
[Detector]      ←  depends on: Analyzer
     │
     ▼
[Classifier]    ←  depends on: Detector
     │
     ├──────────────────────────────────┐
     ▼                                  ▼
[Planner]       ←  depends on:     [Reporter (scan)]
  Classifier + LLM Client (optional)
     │
     ▼
[Migrator]      ←  depends on: Planner + Ingestion + LLM Client
     │
     ▼
[Validator]     ←  depends on: Migrator
     │
     ▼
[Reporter (final)] ← depends on: Validator + Classifier
     │
     ▼
[CLI]           ←  depends on: all modules (orchestration only)
```

### What can be parallelized immediately (no inter-module deps):

- **Models/Utils** — foundation, must be done first (1–2 hours)
- **LLM Client** — independent once Models exist
- **Ingestion** — independent once Models exist
- **Detector pattern library** (pattern definitions, no code) — independent immediately
- **Reporter** (output formatting) — independent once Models exist
- **Test fixtures** (sample crypto code) — independent immediately

---

## 9. Parallelization Plan

### Immediate parallel workstreams (Phase 1)

| Workstream | Tasks | Blocks |
|---|---|---|
| **WS-A** | Models/Utils (done first, ~2h) → Ingestion → Analyzer | Detector, Migrator |
| **WS-B** | LLM Client → Planner | Migrator |
| **WS-C** | Detector pattern library → Classifier risk table | Migrator |
| **WS-D** | Reporter → Validator → CLI wiring | Final integration |

### Task dependency table

| Task ID | Task | Module | Depends on | Blocks | Start |
|---|---|---|---|---|---|
| T-01 | Shared models (models.py) | Utils | — | ALL | Immediate |
| T-02 | Ingestion module | Ingestion | T-01 | T-03 | After T-01 |
| T-03 | Analyzer (AST + call graph) | Analyzer | T-02 | T-04 | After T-02 |
| T-04 | Detector (pattern matching) | Detector | T-03 | T-05 | After T-03 |
| T-05 | Detector pattern library | Detector | T-01 (schema) | T-04 | After T-01 |
| T-06 | Classifier (risk table) | Classifier | T-04 | T-07, T-08 | After T-04 |
| T-07 | LLM Client wrapper | LLM | T-01 | T-08, T-09 | After T-01 |
| T-08 | Planner (strategy selection) | Planner | T-06, T-07 | T-09 | After T-06+T-07 |
| T-09 | Migrator (deterministic transforms) | Migrator | T-08, T-02 | T-10 | After T-08 |
| T-10 | Migrator (LLM-assisted path) | Migrator | T-09, T-07 | T-11 | After T-09 |
| T-11 | Validator | Validator | T-09 | T-12 | After T-09 |
| T-12 | Reporter | Reporter | T-01 | T-13 | After T-01 |
| T-13 | CLI wiring & integration | CLI | ALL | — | Last |
| T-14 | Test fixtures (sample projects) | Tests | — | ALL test tasks | Immediate |
| T-15 | Unit tests: Ingestion+Analyzer | Tests | T-02, T-03 | — | Parallel with T-03 |
| T-16 | Unit tests: Detector+Classifier | Tests | T-04, T-06 | — | Parallel with T-06 |
| T-17 | Integration tests: scan pipeline | Tests | T-06 | — | After T-06 |
| T-18 | Integration tests: migrate pipeline | Tests | T-11 | — | After T-11 |
| T-19 | End-to-end test | Tests | T-13 | — | Last |

---

## 10. Four-Person Work Allocation

### Phase 1 (Foundation + Core Detection)

| Developer | Primary tasks | Notes |
|---|---|---|
| **Dev 1** | T-01 (Models), T-02 (Ingestion), T-03 (Analyzer) | Pipeline foundation — sequential |
| **Dev 2** | T-07 (LLM Client), T-08 (Planner), T-10 (LLM Migration) | IBM watsonx integration |
| **Dev 3** | T-05 (Pattern library), T-04 (Detector), T-06 (Classifier) | Crypto knowledge workstream |
| **Dev 4** | T-14 (Test fixtures), T-12 (Reporter), T-11 (Validator) | Test infra + output layer |

### Phase 2 (Migration + Integration)

| Developer | Primary tasks |
|---|---|
| **Dev 1** | T-09 (Deterministic Migrator transforms) |
| **Dev 2** | T-10 (LLM-assisted migration path) |
| **Dev 3** | T-16, T-17 (Detector+Classifier unit/integration tests) |
| **Dev 4** | T-13 (CLI wiring), T-15 (Ingestion+Analyzer tests) |

### Phase 3 (Hardening + Demo)

All devs: T-18 (migration integration tests), T-19 (end-to-end), demo polish, README.

---

## 11. Git Branching Strategy

### Branch structure

There are exactly **5 long-lived branches**. No additional persistent branches.
Feature work happens on personal branches; PRs merge back to `main`.

```
main                — protected; always demo-ready; final submission state
  ├─ changes-Maruti   — Maruti's active development (repo owner / PR approver)
  ├─ changes-Samik    — Samik's active development
  ├─ changes-Navya    — Navya's active development
  └─ changes-Palak    — Palak's active development
```

**Each developer works only on their personal branch.**
Short-lived `fix/` branches off a personal branch are fine and auto-deleted after merge.

### Merge flow

```
changes-<name>  →  PR (reviewed by Maruti)  →  main
```

- Personal branches are rebased on `main` regularly to stay current.
- PRs require at least **Maruti's approval** before merging to `main`.
- `main` receives a merge commit (not squash) so individual author contributions are visible.

### Rules

1. **`main` is always demo-ready.** Every merge into `main` must leave it buildable and runnable.
2. **Work on your own branch only.** Never commit to another developer's personal branch.
3. **No direct commits to `main`** — use a PR from your personal branch.
4. **Pre-commit hooks** must pass on every commit (`ruff`, `detect-secrets`).
5. **Never commit `.env`** — run `./scripts/check_secrets.sh` before every push.
6. **Commit message format is mandatory** — see `PROMPT.md §6` for the full convention.
7. **Architecture/contract changes** must update `PROJECT_CONTEXT.md` in the same commit.

### Conflict prevention

- Each developer owns a distinct set of modules (see §10) — parallel work rarely touches the same file.
- `src/qsma/utils/models.py` is a shared contract file — any change requires a PR reviewed by all.
- `pyproject.toml` dependencies — communicate additions in the team channel before adding.
- Before starting work each session, rebase on latest `main`: `git fetch origin && git rebase origin/main`.

### Architecture state per branch

This table tracks what is **actually implemented** on each branch at any point in time.
**Update this table in the same commit that implements the feature.**
An AI agent reading this table knows exactly what exists on each branch without
needing to inspect the code.

| Branch | Modules implemented | Phase | Last updated |
|---|---|---|---|
| `main` | Phase 0 stubs: CLI stub, models.py, project structure | Phase 0 | 2024 Phase 0 |
| `changes-Maruti` | (same as main — branch not yet diverged) | Phase 0 | — |
| `changes-Samik` | (same as main — branch not yet diverged) | Phase 0 | — |
| `changes-Navya` | (same as main — branch not yet diverged) | Phase 0 | — |
| `changes-Palak` | (same as main — branch not yet diverged) | Phase 0 | — |

> **Rule:** When you implement a module on your branch, update your row in this table
> in the same commit. Format: `feat(ingestion): ... — updates §11 branch state table`.

---

## 12. Development Phases

### Phase 0 — Foundation (current) ✅

**Objective:** Repository, security, architecture, models, stubs.
**Output:** Working repo, `qsma` CLI stub installs and runs.
**Definition of done:**
- [ ] Git repo initialized with security files
- [ ] `.env.example` with placeholders only
- [ ] `qsma` CLI installs via `pip install -e .`
- [ ] All sub-commands respond (as stubs) without errors
- [ ] `models.py` reviewed and agreed by all developers
- [ ] `PROJECT_CONTEXT.md` complete

---

### Phase 1 — Core Scan Pipeline

**Objective:** `qsma scan <path>` produces real findings on a Python codebase.
**Parallel tasks:** T-02+T-03 (Dev1), T-05+T-06 prep (Dev3), T-14+T-12 (Dev4), T-07 (Dev2)
**Integration point:** Ingestion → Analyzer → Detector → Classifier → Reporter (terminal)
**Definition of done:**
- [ ] `qsma scan tests/fixtures/sample_projects/python_rsa` outputs ≥1 CRITICAL finding
- [ ] JSON output mode works (`--format json`)
- [ ] Unit tests for Ingestion, Analyzer, Detector, Classifier all pass

---

### Phase 2 — Migration Pipeline

**Objective:** `qsma migrate <path>` rewrites RSA → ML-DSA and ECDH → ML-KEM correctly.
**Parallel tasks:** T-09 (Dev1), T-08+T-10 (Dev2), T-15+T-16 tests (Dev3), T-13 CLI (Dev4)
**Integration point:** Planner → Migrator (deterministic) → Validator → Reporter
**Definition of done:**
- [ ] `qsma migrate` on python_rsa fixture produces valid Python that uses Dilithium
- [ ] `--dry-run` shows diff without writing files
- [ ] Validator catches syntax errors in bad transformations
- [ ] `qsma validate` runs pytest on migrated fixture and reports pass/fail

---

### Phase 3 — LLM Integration + Hardening

**Objective:** LLM-assisted migration works for complex/unknown patterns; full demo flow.
**Tasks:** T-10 (Dev2), T-17+T-18 integration tests (Dev3), T-19 e2e (Dev4), polish (all)
**Integration point:** Full pipeline end-to-end with real watsonx.ai calls
**Definition of done:**
- [ ] LLM-assisted migration produces valid code for at least one complex pattern
- [ ] End-to-end test on a real open-source Python project (with crypto) completes
- [ ] Markdown report output correct and readable
- [ ] README complete with demo instructions
- [ ] All secrets checks pass

---

### Phase 4 — Demo Polish

**Objective:** Submission-ready demo.
- Compelling sample project with RSA + ECDH vulnerabilities
- Full `scan → migrate → validate` flow runs in < 60 seconds
- Markdown report ready for submission
- Presentation narrative matches the tool output

---

## 13. Testing Strategy

### Layers

| Layer | Scope | Tool | When |
|---|---|---|---|
| Unit | Each module in isolation | pytest | During module development |
| Integration | Multi-module pipelines | pytest | After Phase 1 integration |
| E2E | Full CLI `scan → migrate → validate` | pytest + subprocess | Phase 3 |
| Security | No secrets in repo | detect-secrets + check_secrets.sh | Every commit |

### Test fixtures

Located in `tests/fixtures/sample_projects/`:
- `python_rsa/` — simple script using RSA-2048 sign/verify
- `python_ecdh/` — ECDH key exchange example
- `python_aes/` — AES-128 CBC encryption

These fixtures are **deliberately vulnerable** — this is by design for testing.

### Migration correctness criteria (Phase 2 tests)

A migration test passes only when:
1. The modified file parses without syntax errors
2. The detected algorithm in the output is a NIST PQC standard
3. The non-cryptographic code in the file is byte-identical to the original
4. Where applicable, the modified project's test suite still passes

---

## 14. Technology Decisions

| Technology | Purpose | Decision rationale |
|---|---|---|
| **Python 3.x** | Primary language | Team familiarity; excellent crypto + AST libraries |
| **Click** | CLI framework | Mature, composable, well-tested |
| **Rich** | Terminal output | Beautiful, zero-config tables/progress bars |
| **libcst** | AST transformations | Lossless CST — preserves formatting/comments; unlike `ast` module which does not roundtrip |
| **Pydantic v2** | Data models/contracts | Fast validation; typed interface enforcement between modules |
| **openai (Python SDK)** | LLM integration | OpenAI-compatible API — works with OpenAI, Anthropic gateways, watsonx.ai, and any compatible provider; switch provider via env vars only, no code change |
| **python-dotenv** | Env var loading | Standard approach; never hardcodes credentials |
| **pytest** | Test framework | Standard; integrates with coverage |
| **ruff** | Linting + formatting | Fast; replaces flake8 + isort + black |
| **detect-secrets** | Secret scanning | Pre-commit integration; IBM security requirement |
| **pre-commit** | Git hooks | Enforces quality + security gates before commits |

### Why libcst over ast module

`ast` does not roundtrip (it cannot reconstruct source from an AST preserving
comments and formatting). `libcst` operates on a Concrete Syntax Tree that preserves
all whitespace, comments, and formatting, making it suitable for automated code
transformation tools that must produce readable, PR-mergeable output.

### LLM provider — OpenAI-compatible interface

The LLM client (`src/qsma/llm/client.py`) uses the **OpenAI Chat Completions API**.
This is a de-facto standard implemented by:

| Provider | `LLM_BASE_URL` | Example `LLM_MODEL` |
|---|---|---|
| OpenAI | *(leave blank)* | `gpt-4o` |
| Anthropic (via gateway) | provider-specific | `claude-3-5-sonnet-20241022` |
| IBM watsonx.ai | `https://<region>.ml.cloud.ibm.com/ml/v1/text/chat` | `ibm/granite-34b-code-instruct` |
| Local / Ollama | `http://localhost:11434/v1` | `codellama` |

**Switching provider = changing `.env` only. Zero code change.**

The LLM is used **only** in:
1. Planner — generating migration strategies for complex/ambiguous patterns
2. Migrator — LLM-assisted transformation when deterministic rules are insufficient

NOT used for:
- Detection (deterministic — must be 100% reproducible)
- Risk classification (deterministic — based on fixed NIST risk table)
- Validation (deterministic — syntax check + test execution)

### Data storage and caching

**This tool is stateless by default.** No database. No persistent state between runs.

| Mechanism | Purpose | Location | Phase |
|---|---|---|---|
| **JSON scan cache** | Skip re-scanning unchanged files | `.qsma_cache/<sha256-hash>.json` | Phase 1 |
| **In-process registry** | `dict[finding_id → CryptoFinding]` within a single CLI invocation | `src/qsma/utils/registry.py` | Phase 1 |
| **No database** | No SQLite, PostgreSQL, Redis — out of MVP scope | — | Out of scope |
| **No inter-run persistent state** | Fresh scan each run unless `--cache` flag passed | — | Phase 1 flag |

**Cache design:**
- Cache key: `sha256(sorted list of (absolute_file_path, file_mtime_ns))` for the scanned tree
- A single changed file invalidates only that file's findings, not the whole scan
- Cache is stored locally in `.qsma_cache/` (excluded from git via `.gitignore`)
- Cache format: `ScanReport` serialized to JSON via `model.model_dump_json()`

---

## 15. Architectural Decision Log (ADR)

> Record every significant architectural decision here before implementing it.
> Future AI sessions and developers MUST NOT casually change these decisions.

### ADR-001: Python-only MVP

**Date:** 2024 (Phase 0)
**Decision:** MVP targets Python codebases only.
**Reason:** Hackathon time constraint; `libcst` provides excellent Python support;
team is Python-native.
**Impact:** Architecture is language-agnostic at the module boundary level —
Ingestion and Analyzer are designed to accept language hints for future extension.
**Status:** Accepted

---

### ADR-002: Deterministic rules are primary; LLM is fallback

**Date:** 2024 (Phase 0)
**Decision:** Detection and risk classification are always deterministic.
LLM is used only for migration planning and transformation of complex patterns.
**Reason:** Security-sensitive classification must be auditable and reproducible.
LLM outputs for cryptographic recommendations must not vary across runs.
**Impact:** Detector and Classifier have zero LLM dependency.
**Status:** Accepted

---

### ADR-003: libcst for code transformation

**Date:** 2024 (Phase 0)
**Decision:** Use `libcst` for all Python AST transformations in the Migrator.
**Reason:** Lossless CST; preserves formatting/comments; purpose-built for codemods.
**Impact:** Migrator module requires libcst. All transformers extend `libcst.CSTTransformer`.
**Status:** Accepted

---

### ADR-004: Shared models in utils/models.py are frozen contracts

**Date:** 2024 (Phase 0)
**Decision:** `CryptoFinding`, `MigrationPlan`, `TransformationResult`, `ValidationResult`,
`ScanReport` are the canonical inter-module data exchange types.
**Reason:** Parallel development requires stable interfaces.
**Impact:** Any schema change to these models requires a PR that all developers review.
**Status:** Accepted

---

### ADR-005: No web frontend in any phase

**Date:** 2024 (Phase 0)
**Decision:** The product is CLI-only. No Flask/FastAPI web server, no HTML output
beyond the Markdown report format.
**Reason:** Explicit product requirement; reduces scope to achievable hackathon target.
**Status:** Accepted

---

## 16. Known Risks

| Risk | Severity | Mitigation |
|---|---|---|
| libcst transformation accuracy for edge cases | High | Comprehensive test fixtures; fallback to LLM path |
| pqcrypto / oqs-python library availability and API stability | Medium | Abstract behind Migrator — swap library without changing interface |
| watsonx.ai API rate limits / latency during demo | Medium | LLM path is optional; deterministic path always works |
| NIST PQC library not yet in Python stdlib | Medium | Use `liboqs-python` (Open Quantum Safe project) for Kyber/Dilithium |
| Complex crypto usage patterns not covered by rules | Medium | LLM fallback + clear "manual review required" output |
| Test fixture crypto code triggers static analysis warnings | Low | Document fixtures as intentionally vulnerable |
| Merge conflicts on shared models.py | Low | PR review process + team communication channel |

---

## 17. Current Status

**Phase:** 0 — Foundation

| Item | Status |
|---|---|
| Git repository initialized | ✅ |
| `.gitignore` with IBM security patterns | ✅ |
| `.bobignore` | ✅ |
| `.env.example` with placeholders | ✅ |
| `pyproject.toml` | ✅ |
| Directory structure | ✅ |
| `src/qsma/utils/models.py` (shared contracts) | ✅ |
| `src/qsma/cli/main.py` (stub commands) | ✅ |
| `tests/conftest.py` | ✅ |
| `.pre-commit-config.yaml` | ✅ |
| `scripts/check_secrets.sh` | ✅ |
| `PROJECT_CONTEXT.md` | ✅ |
| `README.md` | ✅ (written below) |
| All sub-commands run as stubs | ⬜ (needs `pip install -e .`) |
| `models.py` reviewed by team | ⬜ |

**Nothing beyond Phase 0 has been implemented yet.**

---

## 18. Next Tasks

The immediate next steps after Phase 0 review:

1. **Team:** Review and agree on `models.py` — this is the contract all modules depend on.
   If changes are needed, make them NOW before parallel development starts.

2. **Dev 1:** Create `feat/ingestion-analyzer` branch.
   Implement `qsma.ingestion` (T-02) and `qsma.analyzer` (T-03).
   Start with `CodebaseSnapshot` and `IngestionConfig`.

3. **Dev 2:** Create `feat/llm-client-planner` branch.
   Implement `qsma.llm` client wrapper (T-07).
   Ensure it mocks cleanly in tests — watsonx credentials not required for unit tests.

4. **Dev 3:** Create `feat/detector-classifier` branch.
   Define the detection rule schema in `qsma.detector.patterns` (T-05).
   Build the risk table in `qsma.classifier` (part of T-06).

5. **Dev 4:** Create `feat/reporter-validator` branch.
   Implement `qsma.reporter` (T-12) against the existing `CryptoFinding` schema.
   Create sample project fixtures in `tests/fixtures/` (T-14).

**Phase 1 integration checkpoint:** When Dev 1 completes Analyzer, schedule a 30-min
integration session to wire Ingestion → Analyzer → Detector (stub) and verify the
data contracts hold in practice.

