# PROMPT.md — AI Session Bootstrap Guide
## Quantum-Safe Crypto Migration Agent (`qsma`)

---

> **READ THIS FILE FIRST.**
> This is the mandatory entry point for every new AI session working on this project.
> A context window reset means nothing carries over. Start here, every time.

---

## Step 1 — Read PROJECT_CONTEXT.md

**[`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) is the single source of truth.**

Read it before writing, modifying, refactoring, or planning any code.

It contains:

| Section | What it covers |
|---|---|
| §1–3 | What the product is, the problem it solves, and what is in/out of scope |
| §4 | The agreed pipeline architecture (diagram) |
| §5–6 | Every module, its responsibility, inputs, outputs, interfaces |
| §7 | Inter-module data contracts (`models.py` schemas) |
| §8–9 | Task dependency DAG and parallelization plan |
| §10 | Git branching strategy |
| §11 | Development phases and definitions of done |
| §12 | Testing strategy |
| §13 | Technology decisions (LLM provider, libraries, DB/cache policy) |
| §14 | Architectural Decision Log — ADRs that must not be casually overridden |
| §15 | Known risks |
| §16 | **Current status — what has actually been implemented** |
| §17 | **Next tasks — what to work on right now** |

---

## Step 2 — Orientation checklist (answer before starting)

- [ ] What **branch** am I on? Does it match my developer branch (`changes-Maruti` etc.)?
- [ ] What is the **current development phase**? (§11 / §16)
- [ ] What is the **assigned task** for this session? (§17)
- [ ] What **upstream contracts** does this module consume? (§7 + `src/qsma/utils/models.py`)
- [ ] What **downstream modules** consume what I produce? (§8 DAG)
- [ ] Are there **ADRs** (§14) that constrain my approach?
- [ ] What has **already been implemented**? (§16)
- [ ] Does the **architecture state** for my branch match `ARCHITECTURE.md`?

---

## Step 3 — Branch and architecture state

Each developer works exclusively on their personal branch.
**Check which branch you are on before any commit.**

```
git branch --show-current
```

Expected branches:

| Branch | Owner | GitHub |
|---|---|---|
| `main` | Maruti (repo owner) | `vmrt-india` |
| `changes-Maruti` | **Maruti** | `vmrt-india` |
| `changes-Samik` | **Samik** | — |
| `changes-Navya` | **Navya** | — |
| `changes-Palak` | **Palak** | — |

**Each developer works only on their own branch and merges to `main` when ready.**
Maruti (`vmrt-india`) is repo owner and coordinates merges.

**Before merging into `main`**, update your row in the
[`ARCHITECTURE.md` branch state table](ARCHITECTURE.md#per-branch-architecture-state)
in the same commit to reflect what you implemented.

---

## Step 4 — Screenshot your session (required)

At the end of every Bob session, **take a screenshot and add it to your folder**.

```
bob_sessions/<YourName>/YYYY-MM-DD_HH-MM_<brief-description>.png
```

### Workflow (every session, every developer)

```bash
# 1. Make sure you are on your personal branch
git checkout changes-<YourName>

# 2. Drop your screenshot into your folder
#    (right-click the Bob chat session info panel → Save Image, or drag to folder)

# 3. Commit it
git add bob_sessions/<YourName>/<screenshot>.png
git commit -m "docs(bob_sessions): <YourName> — <brief description of session work>"

# 4. Push your branch
git push origin changes-<YourName>

# 5. Merge to main
git checkout main
git merge --ff-only changes-<YourName>
git push origin main
```

### Why this matters

The IBM Dev Day Hackathon requires **evidence of each team member's individual
contribution**. Screenshots of Bob sessions are that evidence.
A session with no screenshot is a session that cannot be counted.

### Rules

- No credentials or sensitive data visible — blur/crop before saving.
- Name files with date + time + brief description so judges can follow the sequence.
- Add to **your own folder only** (`bob_sessions/Maruti/`, `bob_sessions/Samik/`, etc.).
- Commit on **your personal branch first**, then merge to `main`.

---

## Step 5 — What you must NOT do

- **Do not redesign the pipeline** without adding an ADR to `PROJECT_CONTEXT.md §14` first.
- **Do not redefine data models** in individual modules — only `src/qsma/utils/models.py`.
- **Do not add a module** that duplicates an existing module's responsibility.
- **Do not hardcode any credentials** — not in code, not in comments, not in tests.
- **Do not commit `.env`** — run `./scripts/check_secrets.sh` before every push.
- **Do not commit directly to `main`** — use your personal branch and raise a PR.
- **Do not let `PROJECT_CONTEXT.md` fall out of sync** with what is actually implemented.

---

## Step 6 — The DAG and initial files are provisional, not fixed

The task dependency graph (`PROJECT_CONTEXT.md §8–9`) and the stub files created in
Phase 0 are **starting points, not permanent fixtures**.

**What is explicitly allowed to change:**

| Item | How to change it |
|---|---|
| Task IDs / task breakdown in the DAG | Update §8 and §9 in `PROJECT_CONTEXT.md`; commit with `arch:` type |
| Module split/merge | Write an ADR (§14), update §5–6, update `models.py` if contracts change |
| `models.py` data schemas | PR with all developers reviewing; add ADR entry |
| Technology choices (LLM provider, libraries) | Write an ADR (§14); update §13 |
| Phase definitions and scope | Update §11; note what changed and why |
| Stub files in `src/qsma/` | Skeletons — replace entirely with real implementations |
| Test fixtures | Add/modify freely; keep them clearly labelled as intentionally vulnerable |

**The only truly frozen things are ADRs with `Status: Accepted`.**
Even those can change — but need an explicit superseding ADR before implementation.

---

## Step 7 — Commit message rules

**Git is the changelog.** No separate CHANGELOG file is maintained.
Every commit message must be precise enough that a developer reading `git log`
knows exactly what changed and why.

### Format (Conventional Commits — required)

```
<type>(<scope>): <imperative summary, ≤72 chars>

[body — explain WHY, not just WHAT. Wrap at 80 chars.]

[footer — task IDs, ADR refs, breaking changes]
```

### Types

| Type | When to use |
|---|---|
| `feat` | New feature or new module implementation |
| `fix` | Bug fix |
| `refactor` | Code restructure, no behavior change |
| `chore` | Build system, deps, tooling, config |
| `test` | Tests only |
| `docs` | Documentation only (PROJECT_CONTEXT.md, PROMPT.md, README, etc.) |
| `arch` | ADR addition or architectural decision update |
| `contract` | Change to `src/qsma/utils/models.py` inter-module contracts |
| `security` | Security-related changes (.gitignore, secrets, env vars) |

### Scopes (use the module name)

`cli` · `ingestion` · `analyzer` · `detector` · `classifier` · `planner`
`migrator` · `validator` · `reporter` · `llm` · `agent` · `session` · `models` · `tests` · `config` · `docs`

### Good commit message examples

```
feat(ingestion): implement CodebaseSnapshot with .gitignore-aware file walker

Walks target path recursively using pathspec for exclude patterns.
Filters by configured extensions (.py default), skips binary files
and files exceeding max_file_size config.

Implements T-02. Unblocks T-03 (Analyzer).
```

```
contract(models): split CryptoHit from CryptoFinding

Previously Detector produced CryptoFinding directly, conflating
detection and classification. CryptoHit is now the raw detection
output; CryptoFinding is the classified result.

See ADR-006 in PROJECT_CONTEXT.md §14.
Breaking: Classifier now consumes list[CryptoHit], not raw nodes.
```

```
fix(detector): handle aliased crypto imports (import rsa as myrsa)

Detector missed usage when crypto libraries were imported under an
alias. Added alias resolution in ImportRef tracking.
```

```
arch: ADR-006 — split CryptoHit from CryptoFinding

Detection and classification were conflated in original design.
Splitting produces cleaner module boundaries and independent tests.
PROJECT_CONTEXT.md §14 updated in this commit.
```

### Bad commit messages (never use)

```
fix bug
update code
changes
WIP
add models
refactor detector
```

### Rule: architecture changes and contract changes must update PROJECT_CONTEXT.md in the same commit

Never let the document drift from the code.
If you change `models.py`, change a module boundary, change the DAG,
or make a technology decision — update `PROJECT_CONTEXT.md` in the same commit.

---

## Step 8 — LLM provider

The LLM client (`src/qsma/llm/client.py`) is **provider-agnostic**. Default is IBM watsonx.ai.

| `LLM_PROVIDER` value | SDK | Credentials |
|---|---|---|
| `watsonx` *(default)* | `ibm-watsonx-ai` | `WATSONX_API_KEY`, `WATSONX_PROJECT_ID`, `WATSONX_URL` |
| `openai_compatible` | `openai` | `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` |
| `anthropic_compatible` | `anthropic` | `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` |

**No code change is needed to switch providers — only `.env` changes.**

See `.env.example` for all variables. See `src/qsma/llm/client.py` for the implementation.

The LLM is used in **all three migration agents** (Planner, Migrator, Validator — all LangGraph nodes):
- **Planner** — reasons about migration strategy; produces `MigrationPlan`
- **Migrator** — generates transformed code from the original snippet + plan
- **Validator** — interprets test/syntax failures; produces `retry_hints` for Migrator

The LLM is **not** used in: Ingestion, Analyzer, Detector, Classifier — these are fully deterministic.

---

## Step 9 — Data storage and caching

| Mechanism | Purpose | Location | Phase |
|---|---|---|---|
| **Redis session cache** | Store `MigrationSessionState` per session; enable `--resume` | `REDIS_URL` in `.env` (default `redis://localhost:6379`) | Phase 2 |
| **JSON scan cache** | Avoid re-scanning unchanged files between `qsma scan` runs | `.qsma_cache/<sha256-hash>.json` | Phase 1 |
| **In-process finding registry** | `dict[finding_id → CryptoFinding]` per CLI invocation | `src/qsma/utils/registry.py` | Phase 1 |
| **Agent training data** | Few-shot examples + system prompts for LangGraph agents | `src/qsma/llm/training_data/` | Phase 2 |
| **No persistent DB** | No SQLite, PostgreSQL — out of MVP scope | — | Out of scope |

**Redis** (`src/qsma/utils/session.py`) is optional at runtime — if unavailable, the tool runs in
stateless mode (no `--resume` capability) and prints a warning. TTL: 24h (configurable via
`REDIS_SESSION_TTL_SECONDS` in `.env`).

**JSON scan cache key:** `sha256` of sorted `(file_path, mtime_ns)` pairs.
A changed file invalidates only that file's findings, not the entire scan.

---

## Step 10 — Security rules

1. `.env` is never committed — `git status` before every push.
2. API keys go in `.env` only — never in source, never in comments, never in tests.
3. `.env.example` contains placeholders only (`your_api_key_here`).
4. Run `./scripts/check_secrets.sh` before pushing.
5. Run `pre-commit install` on first clone.
6. The LLM client reads credentials from environment variables at runtime only.

---

## Step 11 — Quick reference

| Question | Where to look |
|---|---|
| What files exist and what do they contain? | `ARCHITECTURE.md` — file index |
| What is the current architecture? | `ARCHITECTURE.md` — pipeline diagram |
| What is implemented on each branch right now? | `ARCHITECTURE.md` — branch state table |
| Full module specs, DAG, parallelization plan? | `PROJECT_CONTEXT.md §4–9` |
| What does module X do? | `PROJECT_CONTEXT.md §6.X` |
| What data does module X produce/consume? | `PROJECT_CONTEXT.md §7` + `src/qsma/utils/models.py` |
| What task to work on? | `PROJECT_CONTEXT.md §17` |
| What ADRs constrain me? | `PROJECT_CONTEXT.md §14` |
| Which branch is mine? | `PROJECT_CONTEXT.md §10` |
| What LLM provider is configured? | `.env` → `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL` |
| What env vars are needed? | `.env.example` |
| How to write commit messages? | `PROMPT.md §7` (this file) |
| Can I change the DAG? | Yes — see `PROMPT.md §6` |
| Can I change `models.py`? | Yes, with PR + ADR — see `PROMPT.md §6` |
| Is there a database? | No persistent DB. Redis for session state — see `PROMPT.md §9` |
| Is there caching? | Redis (session) + JSON scan cache — see `PROMPT.md §9` |
| What is the migration strategy for all findings? | LLM-agentic (Planner→Migrator→Validator); no deterministic rewrite — see ADR-002 |
| Can I add a rule-based transform path to Migrator? | No — see ADR-002 and ADR-003 |
| Where do session screenshots go? | `bob_sessions/<YourName>/` — see `PROMPT.md §4` |

---

*Keep this file and `PROJECT_CONTEXT.md` in sync.
If a rule here conflicts with `PROJECT_CONTEXT.md`, `PROJECT_CONTEXT.md` governs.*
