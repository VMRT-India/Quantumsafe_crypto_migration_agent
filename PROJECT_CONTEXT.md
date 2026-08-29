# PROJECT_CONTEXT.md
## Quantum-Safe Crypto Migration Agent — Master Project Context

> **CANONICAL SOURCE OF TRUTH**
> Every developer and every future AI session MUST read this document before starting work.
> Do NOT redesign components without updating this document first.
> Do NOT duplicate functionality described here.
> When a significant architectural change is necessary, record it in §14 (ADR Log) before implementing it.

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
10. [Git Branching Strategy](#10-git-branching-strategy)
11. [Development Phases](#11-development-phases)
12. [Testing Strategy](#12-testing-strategy)
13. [Technology Decisions](#13-technology-decisions)
14. [Architectural Decision Log (ADR)](#14-architectural-decision-log-adr)
15. [Known Risks](#15-known-risks)
16. [Current Status](#16-current-status)
17. [Next Tasks](#17-next-tasks)

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
| Language support | Python (primary); Java, Go, C, Rust via tree-sitter parsing (detection only — AST transforms remain Python/libcst for MVP) |
| Detection | RSA, ECDSA, ECDH, DSA, DH, AES-128, DES, 3DES, MD5, SHA-1 |
| Libraries detected | `cryptography`, `pycryptodome`, `hashlib`, `hmac`, `ssl`, `paramiko` (Python); standard crypto APIs per language (Java, Go, C, Rust) |
| Risk classification | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| Migration targets | ML-KEM (Kyber), ML-DSA (Dilithium), AES-256, SHA-256+ |
| Migration method | Deterministic AST rewrites (primary, Python only via libcst) + LangGraph agentic loop (Planner → Migrator → Validator → retry) + LLM-assisted fallback |
| Validation | Syntax check, optional `pytest` execution, optional `pip install` check; validator feeds back into LangGraph retry loop |
| CLI interface | `scan`, `report`, `migrate`, `validate` commands; `--resume <session_id>` for interrupted runs |
| IBM technology | watsonx.ai (Granite Code model) as default LLM backend for LangGraph agents |
| Output formats | terminal (rich), JSON, Markdown |
| Session persistence | Redis — stores pipeline state per session; enables mid-run resume |
| Agent training data | `src/qsma/llm/training_data/` — few-shot examples + prompt templates per algorithm family |

### Explicitly out of scope (MVP)

- Web UI / dashboard
- AST-level code transforms for non-Python languages (detection works; automated rewrite is Python-only for MVP)
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
1. **Planner agent** — LangGraph node: reasons about migration strategy; multi-step for complex/unknown patterns
2. **Migrator agent** — LangGraph node: applies transformation; iterates if Validator reports failure
3. **Validator agent** — LangGraph node: interprets test failures; signals retry to Migrator or escalates to manual
4. **Classifier** — optional enrichment of explanation text (can be disabled)

The LLM is **not** used for detection or risk classification — these are deterministic.

### Agentic loop (Planner → Migrator → Validator)

```
list[CryptoFinding]
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  LangGraph  MigrationGraph                          │
│                                                     │
│  ┌──────────┐    plan     ┌──────────┐              │
│  │ Planner  ├────────────►│ Migrator │              │
│  │  agent   │             │  agent   │              │
│  └──────────┘             └────┬─────┘              │
│        ▲                       │ TransformationResult│
│        │  retry (replan)       ▼                    │
│        │               ┌──────────────┐             │
│        └───────────────┤  Validator   │             │
│                        │   agent      │             │
│                        └──────┬───────┘             │
│                               │ pass / escalate     │
└───────────────────────────────┼─────────────────────┘
                                ▼
                        ValidationResult
```

- Each node is a LangGraph `StateGraph` node backed by `LLMClient` (watsonx.ai)
- State is a `MigrationSessionState` Pydantic model persisted to Redis per session
- Max retry depth: 3 (configurable). After 3 failures → `MigrationStatus.MANUAL_REQUIRED`
- Deterministic findings bypass the agent loop entirely (direct libcst transform)

### Shared utilities

`src/qsma/utils/models.py` — Pydantic data models (the shared contract layer)
`src/qsma/llm/` — watsonx.ai client wrapper, prompt templates, response parsing
`src/qsma/llm/training_data/` — few-shot migration examples + prompt templates (JSON/YAML per algorithm family)
`src/qsma/utils/session.py` — Redis session manager; serialize/deserialize `MigrationSessionState`

---

## 5. Module Catalogue

| Module | Package | Responsibility |
|---|---|---|
| CLI | `qsma.cli` | Command routing, user interaction, progress display; `--resume` flag |
| Ingestion | `qsma.ingestion` | Filesystem walk, file filtering, raw source collection |
| Analyzer | `qsma.analyzer` | Multi-language AST parsing via tree-sitter (all languages) + libcst for Python structural analysis |
| Detector | `qsma.detector` | Pattern matching on tree-sitter AST nodes to find crypto usage across languages |
| Classifier | `qsma.classifier` | Risk scoring, algorithm identification, recommendation |
| Planner | `qsma.planner` | **LangGraph agent node** — migration strategy reasoning per finding |
| Migrator | `qsma.migrator` | **LangGraph agent node** — code transformation (libcst deterministic + LLM-assisted) |
| Validator | `qsma.validator` | **LangGraph agent node** — post-migration build/test validation; feeds back to Migrator on failure |
| Reporter | `qsma.reporter` | Output formatting (terminal, JSON, Markdown) |
| LLM Client | `qsma.llm` | watsonx.ai SDK wrapper, prompt templates, few-shot training data loader |
| Session | `qsma.utils.session` | Redis-backed session state manager; serialize/resume `MigrationSessionState` |
| Models | `qsma.utils.models` | Shared Pydantic data-models (contracts) including `MigrationSessionState` |

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

**Purpose:** Parse source files into language-specific ASTs and extract structural information for all supported languages.

**Inputs:** `CodebaseSnapshot`
**Outputs:** `AnalysisResult` — per-file parsed tree + import map + call sites

**Responsibilities:**
- Detect the language of each `SourceFile` by extension (`.py`, `.java`, `.go`, `.c`, `.rs`, etc.)
- Parse each file using **tree-sitter** (universal parser for all languages)
- For Python files, additionally build a `libcst` CST tree (stored alongside — needed by Migrator for lossless transforms)
- Extract: imports, function definitions, class definitions, call expressions — via tree-sitter query language
- Build a lightweight intra-file call graph
- Identify which imports are cryptographic in origin (using a per-language import allowlist)

**Language support matrix:**
| Language | Parser | Detection | AST Transform |
|---|---|---|---|
| Python | tree-sitter + libcst | ✅ | ✅ libcst (lossless) |
| Java | tree-sitter | ✅ | ❌ manual only (MVP) |
| Go | tree-sitter | ✅ | ❌ manual only (MVP) |
| C / C++ | tree-sitter | ✅ | ❌ manual only (MVP) |
| Rust | tree-sitter | ✅ | ❌ manual only (MVP) |

**Key classes:**
```
ParsedFile     — path, language, ts_tree, cst_tree (Python only), imports, call_sites
ImportRef      — module, alias, line, language
CallSite       — function_name, arguments, line, enclosing_function, language
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

**Purpose:** For each selected `CryptoFinding`, reason about the correct migration strategy and produce an actionable `MigrationPlan`. Implemented as a **LangGraph agent node** — always calls the LLM.

**Inputs:** `list[CryptoFinding]` (selected subset), `MigrationSessionState` (from Redis)
**Outputs:** `list[MigrationPlan]`, updated `MigrationSessionState`

**Responsibilities:**
- Call `LLMClient` with a structured prompt that includes: the detected algorithm, the usage type, the code snippet, the NIST PQC target, and relevant few-shot examples from `training_data/few_shot/`
- Parse the LLM response into a `MigrationPlan`: target algorithm, required dependency changes (`requirements.txt` / `go.mod` / `pom.xml`), and `transformation_hints` for the Migrator
- For non-Python findings where automated migration is not supported: produce `MigrationPlan(strategy=manual_only)` with an explanation — no LLM call needed
- Persist each `MigrationPlan` to Redis session as it is produced (enables resume)

**Target algorithm mapping (provided as context in the LLM prompt — not hard-coded rules):**
```
RSA  (any usage)   → ML-DSA (Dilithium)   FIPS 204
ECDSA, DSA, DH     → ML-DSA (Dilithium)   FIPS 204
ECDH               → ML-KEM (Kyber)       FIPS 203
AES-128, DES, 3DES → AES-256              NIST SP 800-131A
Unknown            → LLM reasons freely   (no pre-set target)
Non-Python         → manual_only          (detection report only)
```

**LangGraph node:** `planner_node(state: MigrationSessionState) → MigrationSessionState`
- Calls `LLMClient` for every Python finding; parses structured JSON `MigrationPlan` from response
- Routes directly to `migrator_node` per finding

**Depends on:** Classifier output (list[CryptoFinding]), LLM Client, Session (Redis), training_data/

---

### 6.6 Migrator (`qsma.migrator`)

**Purpose:** Transform source files from quantum-vulnerable crypto to NIST PQC equivalents. Fully LLM-driven. Implemented as a **LangGraph agent node** that retries on Validator feedback.

**Inputs:** `list[MigrationPlan]`, `CodebaseSnapshot`, `MigrationSessionState` (from Redis)
**Outputs:** `list[TransformationResult]`, updated `MigrationSessionState`

**Responsibilities:**
- Receive a `MigrationPlan` from the Planner node (includes finding, target algorithm, transformation hints, few-shot examples)
- Construct a prompt that contains: the original code snippet, the detected algorithm, the target algorithm, dependency context, and relevant few-shot examples from `training_data/`
- Call `LLMClient` to generate the transformed code fragment
- Use `libcst` to splice the LLM-produced fragment back into the source file at the detected location, preserving surrounding code, comments, and formatting (libcst is a file-write utility here — not the migration logic)
- On first attempt failure signal from Validator: incorporate `retry_hints` into the next prompt and retry (max 3 attempts)
- Write transformed files atomically (dry-run mode: produce diff only, no file writes)
- Persist `TransformationResult` to Redis session after each file (enables resume)

**Sub-modules:**
```
migrator/llm_transform.py — builds LLM prompt from MigrationPlan + few-shot + code context; parses response
migrator/patcher.py       — uses libcst to splice LLM output into source file at correct location (atomic write)
```

**LangGraph node:** `migrator_node(state: MigrationSessionState) → MigrationSessionState`
- Reads `state.pending_plans`, processes one finding at a time, writes result back to state
- Routes to `validator_node` after each transform; routes back to self on retry signal from Validator

**Safety invariants:**
- The LLM prompt MUST include the exact detected code snippet (from `CryptoFinding.location.snippet`) so the LLM has precise context
- libcst splice MUST NOT modify code outside the finding's `line_start`–`line_end` range
- All file modifications are atomic (write to temp → move on success)
- Dry-run mode must produce the same diff as a real run, minus the file write
- Non-Python files: produce `TransformationResult(success=False, error="non-Python transform not supported in MVP")`

**Depends on:** Planner (MigrationPlan), Ingestion (CodebaseSnapshot), LLM Client, Session (Redis), training_data/

---

### 6.7 Validator (`qsma.validator`)

**Purpose:** Verify post-migration correctness of the codebase. Implemented as a **LangGraph agent node** that signals pass, retry, or escalate.

**Inputs:** `list[TransformationResult]`, `target_path: Path`, `MigrationSessionState` (from Redis)
**Outputs:** `ValidationResult`, updated `MigrationSessionState` with signal: `pass | retry | escalate`

**Validation steps (in order):**
1. **Syntax check** — parse all modified files with `ast.parse` (Python) or tree-sitter (other languages); fast, always runs
2. **Dependency check** — if new packages required, attempt `pip install --dry-run` (Python) or equivalent
3. **Test execution** — if `pytest` / `unittest` tests exist, run them with timeout
4. **Regression detection** — compare test results before/after migration
5. **LLM failure analysis** — if tests fail, call `LLMClient` to interpret failure message and produce `retry_hints` for Migrator

**LangGraph node:** `validator_node(state: MigrationSessionState) → MigrationSessionState`
- On pass: set `state.current_finding_status = COMPLETED`; route to next finding or Reporter
- On syntax/test failure (attempt < 3): set `state.retry_hints`; route back to `migrator_node`
- On failure (attempt == 3): set `state.current_finding_status = MANUAL_REQUIRED`; route to Reporter

**Not responsible for:** Functional correctness of the cryptographic replacement.
That is the responsibility of the Migrator agent (LLM-generated code + retry loop) and the test suite.

**Depends on:** Migrator (TransformationResult), filesystem (for test execution), LLM Client, Session (Redis)

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

## 10. Git Branching Strategy

### Branch structure

There are exactly **5 long-lived branches**. No additional persistent branches.
Feature work happens on personal branches; PRs merge back to `main`.

```
main                — always demo-ready; final submission state
  ├─ changes-Maruti
  ├─ changes-Samik
  ├─ changes-Navya
  └─ changes-Palak
```

**Each developer works only on their own personal branch.**
Short-lived `fix/` branches off a personal branch are fine and auto-deleted after merge.

### Merge flow

```
changes-<name>  →  merge to main  →  push origin main
```

- Personal branches are rebased on `main` regularly to stay current.
- `main` receives a fast-forward or merge commit so individual author commits are visible.

### Rules

1. **`main` is always demo-ready.** Every merge into `main` must leave it buildable and runnable.
2. **Work on your own branch only.** Never commit to another developer's personal branch.
3. **No direct commits to `main`** — use a PR from your personal branch.
4. **Pre-commit hooks** must pass on every commit (`ruff`, `detect-secrets`).
5. **Never commit `.env`** — run `./scripts/check_secrets.sh` before every push.
6. **Commit message format is mandatory** — see `PROMPT.md §7` for the full convention.
7. **Architecture/contract changes** must update `PROJECT_CONTEXT.md` in the same commit.

### Conflict prevention

- Each developer works on separate modules (see §9 parallelization plan) — parallel work rarely touches the same file.
- `src/qsma/utils/models.py` is a shared contract file — any change requires a PR reviewed by all.
- `pyproject.toml` dependencies — communicate additions in the team channel before adding.
- Before starting work each session, rebase on latest `main`: `git fetch origin && git rebase origin/main`.

### Architecture state per branch

This table tracks what is **actually implemented** on each branch at any point in time.
**Update this table in the same commit that implements the feature.**
An AI agent reading this table knows exactly what exists on each branch without
needing to inspect the code.

> Architecture state is tracked in **`ARCHITECTURE.md`** (branch state table).
> Update that file in the same commit as your implementation.


---

## 11. Development Phases

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

**Objective:** `qsma migrate <path>` rewrites RSA → ML-DSA and ECDH → ML-KEM correctly via the LangGraph agentic loop.
**Parallel tasks:** T-09 (Dev1), T-08+T-10 (Dev2), T-15+T-16 tests (Dev3), T-13 CLI (Dev4)
**Integration point:** Planner agent → Migrator agent → Validator agent (→ retry loop) → Reporter
**Definition of done:**
- [ ] `qsma migrate` on python_rsa fixture produces valid Python that uses Dilithium (LLM-generated, agent loop)
- [ ] `--dry-run` shows diff without writing files
- [ ] Validator agent catches syntax errors and triggers a retry with updated hints
- [ ] `qsma validate` runs pytest on migrated fixture and reports pass/fail
- [ ] `qsma migrate --resume <id>` correctly resumes an interrupted session from Redis

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

## 12. Testing Strategy

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

## 13. Technology Decisions

| Technology | Purpose | Decision rationale |
|---|---|---|
| **Python 3.x** | Primary language | Team familiarity; excellent crypto + AST libraries |
| **Click** | CLI framework | Mature, composable, well-tested |
| **Rich** | Terminal output | Beautiful, zero-config tables/progress bars |
| **tree-sitter** | Multi-language AST parsing (Analyzer + Detector) | Universal grammar-based parser for 40+ languages; single consistent query API; primary parser for all language detection |
| **libcst** | Lossless Python source roundtrip (Migrator output only) | After the LLM produces a transformed snippet, libcst is used to splice it into the original file without destroying surrounding formatting and comments. Not used for detection — only for clean file writes. |
| **LangGraph ≥ 0.2** | Agentic orchestration — Planner, Migrator, Validator | Provider-agnostic `StateGraph`; conditional edges for retry loop; Redis checkpointer for session persistence. Planner, Migrator, and Validator are all LangGraph nodes backed by `LLMClient`. |
| **Pydantic v2** | Data models/contracts + LangGraph state | Fast validation; typed interface enforcement between modules; `MigrationSessionState` is the LangGraph graph state |
| **Redis** | Session state persistence + mid-run resume | LangGraph `RedisSaver` checkpointer; key: `qsma:session:<uuid4>`, TTL 24h. Falls back to stateless mode if unavailable. |
| **ibm-watsonx-ai** | LLM backend (default) | Primary/default provider for IBM hackathon; Granite Code model; `LLM_PROVIDER=watsonx` |
| **openai** *(optional extra)* | LLM backend (optional) | `pip install 'qsma[llm-openai]'`; any OpenAI-compatible endpoint; `LLM_PROVIDER=openai_compatible` |
| **anthropic** *(optional extra)* | LLM backend (optional) | `pip install 'qsma[llm-anthropic]'`; any Anthropic-compatible endpoint; `LLM_PROVIDER=anthropic_compatible` |
| **Qdrant** *(optional extra)* | Vector DB for tool/pattern retrieval | Only needed if the number of detection patterns or migration tools grows large enough to require semantic search. Install via `pip install 'qsma[qdrant]'`. Not required for MVP. |
| **python-dotenv** | Env var loading | Standard approach; never hardcodes credentials |
| **pytest** | Test framework | Standard; integrates with coverage |
| **ruff** | Linting + formatting | Fast; replaces flake8 + isort + black |
| **detect-secrets** | Secret scanning | Pre-commit integration; IBM security requirement |
| **pre-commit** | Git hooks | Enforces quality + security gates before commits |

### The migration pipeline is fully LLM-agentic — there is no "deterministic transform" path

Every code migration (Planner → Migrator → Validator) is driven by LLM agents running inside
LangGraph nodes. The LLM reads the `CryptoFinding` (which contains the detected code snippet,
the algorithm, the usage type, and the NIST target), reasons about how to rewrite it, and
produces the transformed code. The Validator agent then checks whether the result is syntactically
valid and passes the existing test suite. If not, it produces `retry_hints` and routes back to
the Migrator agent for another attempt (max 3).

**Why not a rule-based rewriter?** No rule set can reliably rewrite arbitrary crypto call sites
without breaking surrounding logic. Key sizes, parameter names, return types, serialisation formats,
and dependent data structures are coupled in ways that differ across libraries, versions, and usage
patterns. Only an LLM with context over the full call site can reason about all of these simultaneously
and produce correct output.

**The only "deterministic" parts of the system are:**
- **Ingestion** — file walking; always reproducible
- **Analyzer** — tree-sitter parsing; always reproducible
- **Detector** — pattern matching; always reproducible
- **Classifier** — risk scoring via fixed NIST risk table; always reproducible

These four modules have zero LLM dependency. They exist to give the agents precise, grounded
context — the exact file, line, code snippet, algorithm, and risk level — so the LLM agents
can focus entirely on correct code transformation rather than discovery.

### Role of libcst (file write only — not migration logic)

`libcst` is **not** the migration engine. It is used only as a safe file-write mechanism:
once the Migrator agent produces a transformed code snippet, libcst splices it back into
the original source file at the correct location without disturbing surrounding code,
comments, or formatting. This is necessary because the LLM produces a code fragment,
not a whole file, and a raw string replacement would be brittle.

### Why tree-sitter is the primary parser (not libcst)

`libcst` is Python-only. `tree-sitter` provides grammar-based parsing for 40+ languages
using a single, consistent query API. The Analyzer uses tree-sitter to extract imports,
call sites, and identifiers from any supported language.

### Why LangGraph (not a custom agent loop)

LangGraph provides:
- **Typed state graph** — `MigrationSessionState` flows through nodes; inspectable and debuggable
- **Conditional edges** — `migrator_node → validator_node → migrator_node` retry with attempt count
- **Provider-agnostic** — runs over watsonx.ai via `LLMClient` with zero code change to switch providers
- **Redis checkpointer** — `RedisSaver` integrates natively; enables `--resume` with no extra plumbing

### When to use Qdrant (optional, not MVP)

Qdrant is a vector database. It is useful when the agent needs to **retrieve** the most
relevant tool, rule, or example from a large collection before acting. For the MVP, the
number of detection patterns and few-shot examples is small enough to fit in the prompt
directly. If the pattern library grows large (hundreds of rules, many language variants),
Qdrant can be added as a retrieval layer: the agent embeds the `CryptoFinding` description
and retrieves the top-K relevant few-shot examples or migration tools before planning.

### LLM provider architecture

**Default:** IBM watsonx.ai (`ibm-watsonx-ai` SDK, installed with the base package).
**Optional extras:** OpenAI-compatible and Anthropic-compatible providers.

| `LLM_PROVIDER` value | SDK used | Install | Credentials |
|---|---|---|---|
| `watsonx` *(default)* | `ibm-watsonx-ai` | included in base | `WATSONX_API_KEY`, `WATSONX_PROJECT_ID`, `WATSONX_URL` |
| `openai_compatible` | `openai` | `pip install 'qsma[llm-openai]'` | `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` |
| `anthropic_compatible` | `anthropic` | `pip install 'qsma[llm-anthropic]'` | `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` |

**Switching provider = change `LLM_PROVIDER` (+ matching credentials) in `.env`. Zero code change.**

The LLM is used in **all three migration agents**:
1. **Planner node** — reasons about migration strategy; produces `MigrationPlan` with target algorithm, dependency changes, and transformation hints
2. **Migrator node** — reads the finding + plan + original code; produces transformed code snippet
3. **Validator node** — interprets test/syntax failure output; produces `retry_hints` for the Migrator node

NOT used for:
- Ingestion (file walking — no LLM)
- Analyzer (tree-sitter parsing — no LLM)
- Detector (pattern matching — no LLM)
- Classifier (NIST risk table lookup — no LLM)

### Data storage and caching

| Mechanism | Purpose | Location | Phase |
|---|---|---|---|
| **Redis session cache** | Store `MigrationSessionState` per session; enable mid-run resume | `redis://localhost:6379` (configurable via `REDIS_URL` in `.env`) | Phase 2 |
| **JSON scan cache** | Skip re-scanning unchanged files between `qsma scan` invocations | `.qsma_cache/<sha256-hash>.json` | Phase 1 |
| **In-process registry** | `dict[finding_id → CryptoFinding]` within a single CLI invocation | `src/qsma/utils/registry.py` | Phase 1 |
| **training_data/** | Agent few-shot examples + system prompts | `src/qsma/llm/training_data/` | Phase 2 |
| **Qdrant** *(optional)* | Vector retrieval for large pattern/tool libraries | External service; `QDRANT_URL` in `.env` | Post-MVP |
| **No persistent DB** | No SQLite, PostgreSQL — out of MVP scope | — | Out of scope |

**Redis session design:**
- Key: `qsma:session:<uuid4>` → JSON-serialized `MigrationSessionState`
- TTL: 24 hours (configurable via `REDIS_SESSION_TTL_SECONDS` in `.env`)
- Resume: `qsma migrate --resume <session_id>` loads state from Redis, skips completed findings
- Redis is **optional** — if unavailable, tool runs in stateless mode (no resume capability); a warning is printed

**JSON scan cache design:**
- Cache key: `sha256(sorted list of (absolute_file_path, file_mtime_ns))` for the scanned tree
- A single changed file invalidates only that file's findings, not the whole scan
- Cache is stored locally in `.qsma_cache/` (excluded from git via `.gitignore`)
- Cache format: `ScanReport` serialized to JSON via `model.model_dump_json()`

---

## 14. Architectural Decision Log (ADR)

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

### ADR-002: Detection and classification are deterministic; all migration is LLM-agentic

**Date:** 2024 (Phase 0) — **revised 2025**
**Decision:** Detection (Ingestion → Analyzer → Detector → Classifier) is always deterministic
and has zero LLM dependency. All migration work (Planner, Migrator, Validator) is LLM-agentic
via LangGraph nodes backed by watsonx.ai.
**Reason:** Detection and risk classification must be auditable, reproducible, and fast — a rule-based
system is the right tool. Code transformation cannot be reliably rule-based because crypto call sites
are coupled to key sizes, parameter names, return types, serialisation formats, and dependent structures
in ways that vary per library, version, and usage pattern. Only an LLM with full call-site context can
reason about all of these and produce correct output.
**Impact:** Detector and Classifier have zero LLM dependency. Planner, Migrator, and Validator are
all LangGraph nodes — there is no "deterministic transform" path in the Migrator.
**Supersedes:** The original ADR-002 which framed LLM as a fallback. LLM is now the primary migration engine.
**Status:** Accepted

---

### ADR-003: libcst for safe file write after LLM-generated transform (not migration logic)

**Date:** 2024 (Phase 0) — **revised 2025**
**Decision:** `libcst` is used only to splice the LLM-produced code snippet back into the original
source file at the correct location, preserving surrounding formatting and comments.
**Reason:** The LLM produces a transformed code fragment, not a whole file. A raw string replacement
at the detected line range would be brittle. `libcst` provides a lossless CST roundtrip that inserts
the new fragment precisely without disturbing surrounding code.
**Impact:** `libcst` is a file-write utility in the Migrator, not the migration logic itself.
There are no `libcst.CSTTransformer` subclasses implementing migration rules.
**Supersedes:** The original ADR-003 which used libcst as the migration engine.
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

### ADR-006: tree-sitter as primary multi-language parser

**Date:** 2025 (Phase 1 revision)
**Decision:** `tree-sitter` is the primary AST parser for all language detection in the Analyzer and Detector.
`libcst` is retained exclusively for Python code transforms in the Migrator (lossless CST roundtrip).
**Reason:** Architecture is designed for multi-language detection from the start. `tree-sitter` provides a
single, consistent query API for 40+ languages. `libcst` is Python-only and not needed for detection.
**Impact:** Analyzer must use `tree-sitter` grammars per language. Migrator retains `libcst` for Python-only
transforms. The `SourceFile.language` field (set by Ingestion) drives parser selection.
**Supersedes:** ADR-003 partial scope — ADR-003 still governs Migrator transforms; this ADR governs Analyzer/Detector.
**Status:** Accepted

---

### ADR-007: LangGraph for agentic orchestration of Planner → Migrator → Validator

**Date:** 2025 (Phase 2 revision)
**Decision:** Planner, Migrator, and Validator are implemented as LangGraph `StateGraph` nodes.
The migration loop is a LangGraph graph: `planner_node → migrator_node → validator_node`
with conditional edges for retry (up to 3 attempts) and escalation to `MANUAL_REQUIRED`.
**Reason:** A plain function pipeline cannot handle multi-step reasoning, retry with updated hints,
or per-step state persistence. LangGraph provides typed state flow, conditional routing, and
Redis checkpointer integration. It is provider-agnostic — it calls `LLMClient` which routes to watsonx.ai.
**Impact:** `qsma.planner`, `qsma.migrator`, `qsma.validator` each expose a `*_node(state)` function.
A new `src/qsma/agent/graph.py` wires the graph. `MigrationSessionState` Pydantic model is the shared state.
**Status:** Accepted

---

### ADR-008: Redis for session state persistence and mid-run resume

**Date:** 2025 (Phase 2 revision)
**Decision:** `MigrationSessionState` is persisted to Redis using LangGraph's `RedisSaver` checkpointer.
Each session has a UUID4 key with a 24h TTL. Sessions can be resumed with `qsma migrate --resume <id>`.
**Reason:** A migration over a large codebase can take minutes and may be interrupted (network, timeout,
user Ctrl+C). Without persistence, all progress is lost. Redis provides sub-millisecond read/write
for the session JSON blob, and LangGraph has a first-class Redis checkpointer integration.
**Impact:** Redis is a new optional runtime dependency. If Redis is unavailable, the tool falls back
to stateless mode (no resume) with a printed warning. `REDIS_URL` env var configures the connection.
`src/qsma/utils/session.py` is a new module.
**Status:** Accepted

---

### ADR-009: Agent training data stored in src/qsma/llm/training_data/

**Date:** 2025 (Phase 2 revision)
**Decision:** Few-shot migration examples and system prompts for LangGraph agent nodes are stored as
static JSON/text files in `src/qsma/llm/training_data/`. They are loaded at agent startup, not fetched
from a live database.
**Reason:** Hackathon MVP does not require a live training pipeline. Static files are version-controlled,
diffable, reviewable, and immediately available without infrastructure. The schema is designed to be
importable into a fine-tuning pipeline in a future phase.
**Impact:** New directory `src/qsma/llm/training_data/` with `few_shot/` and `prompts/` subdirectories.
The LLM client's prompt-builder functions load from this directory.
**Status:** Accepted

---

### ADR-005: No web frontend in any phase

**Date:** 2024 (Phase 0)
**Decision:** The product is CLI-only. No Flask/FastAPI web server, no HTML output
beyond the Markdown report format.
**Reason:** Explicit product requirement; reduces scope to achievable hackathon target.
**Status:** Accepted

---

## 15. Known Risks

| Risk | Severity | Mitigation |
|---|---|---|
| libcst transformation accuracy for edge cases | High | Comprehensive test fixtures; fallback to LLM path |
| pqcrypto / oqs-python library availability and API stability | Medium | Abstract behind Migrator — swap library without changing interface |
| watsonx.ai API rate limits / latency during demo | Medium | Mock LLM provider available for offline testing; cache scan results so migration can retry without re-scanning |
| NIST PQC library not yet in Python stdlib | Medium | Use `liboqs-python` (Open Quantum Safe project) for Kyber/Dilithium |
| Complex crypto usage patterns not covered by rules | Medium | LLM fallback + clear "manual review required" output |
| Test fixture crypto code triggers static analysis warnings | Low | Document fixtures as intentionally vulnerable |
| Merge conflicts on shared models.py | Low | PR review process + team communication channel |

---

## 16. Current Status

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

## 17. Next Tasks

The immediate next tasks to begin Phase 1:

1. **Review `models.py`** — the inter-module contracts must be agreed before parallel
   development starts. If changes are needed, make them before any module implements
   against the schema.

2. **T-02 Ingestion** — implement `qsma.ingestion`: file walker, `CodebaseSnapshot`,
   `IngestionConfig`. Start here — everything downstream depends on it.

3. **T-07 LLM Client** — implement `qsma.llm` client wrapper. Can start in parallel
   with T-02. Ensure it mocks cleanly — no real credentials needed for unit tests.

4. **T-05 Detector pattern library** — define detection rule schema in
   `qsma.detector.patterns`. Can start in parallel with T-02 and T-07.

5. **T-12 Reporter** — implement `qsma.reporter` against the existing `CryptoFinding`
   schema. Can start immediately — only depends on `models.py` (T-01, done).

6. **T-14 Test fixtures** — expand `tests/fixtures/` with additional sample projects
   covering more crypto patterns. Can start immediately.

**Phase 1 integration checkpoint:** Once T-02 (Ingestion) and T-03 (Analyzer) are
complete, wire Ingestion → Analyzer → Detector stub and verify data contracts hold.

