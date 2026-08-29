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
| §10 | 4-developer work allocation |
| §11 | Git branching strategy and branch ownership |
| §12 | Development phases and definitions of done |
| §13 | Testing strategy |
| §14 | Technology decisions (LLM provider, libraries, DB/cache policy) |
| §15 | Architectural Decision Log — ADRs that must not be casually overridden |
| §16 | Known risks |
| §17 | **Current status — what has actually been implemented** |
| §18 | **Next tasks — what to work on right now** |

---

## Step 2 — Orientation checklist (answer before starting)

- [ ] What **branch** am I on? Does it match my developer branch (`changes-Maruti` etc.)?
- [ ] What is the **current development phase**? (§12 / §17)
- [ ] What is the **assigned task** for this session? (§18 / §10)
- [ ] What **upstream contracts** does this module consume? (§7 + `src/qsma/utils/models.py`)
- [ ] What **downstream modules** consume what I produce? (§8 DAG)
- [ ] Are there **ADRs** (§15) that constrain my approach?
- [ ] What has **already been implemented**? (§17)
- [ ] Does the **architecture state** for my branch in §11 match what I see on disk?

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

- **Do not redesign the pipeline** without adding an ADR to `PROJECT_CONTEXT.md §15` first.
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
| Module split/merge | Write an ADR (§15), update §5–6, update `models.py` if contracts change |
| `models.py` data schemas | PR with all developers reviewing; add ADR entry |
| Technology choices (LLM provider, libraries) | Write an ADR (§15); update §14 |
| Phase definitions and scope | Update §12; note what changed and why |
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
`migrator` · `validator` · `reporter` · `llm` · `models` · `tests` · `config` · `docs`

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

See ADR-006 in PROJECT_CONTEXT.md §15.
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
PROJECT_CONTEXT.md §15 updated in this commit.
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

The LLM client (`src/qsma/llm/`) uses an **OpenAI-compatible Chat Completions API**.

This means it works with any of:

- **OpenAI** (`gpt-4o`, `gpt-4`, etc.)
- **Anthropic** (via OpenAI-compatible gateway)
- **IBM watsonx.ai** (via its OpenAI-compatible endpoint)
- Any self-hosted or third-party provider that implements the OpenAI chat API

**No code change is needed to switch providers.**
The active provider is selected entirely through `.env`:

```
LLM_API_KEY=sk-...             # provider API key
LLM_BASE_URL=https://...       # base URL (leave blank for OpenAI default)
LLM_MODEL=gpt-4o               # model identifier
```

See `.env.example` for all variables.
See `src/qsma/llm/client.py` for the implementation.

The LLM is used **only** in the Planner (strategy generation) and Migrator
(complex pattern transformation). Detection and classification are always
deterministic — they never call the LLM.

---

## Step 9 — Data storage and caching

This tool is **stateless by default**. It reads source files from disk, runs
the pipeline in memory, and produces output. There is no database.

| Mechanism | Purpose | Location | Phase |
|---|---|---|---|
| **JSON scan cache** | Avoid re-scanning unchanged files | `.qsma_cache/<hash>.json` | Phase 1 |
| **In-process finding registry** | `dict[finding_id → CryptoFinding]` per CLI run | `src/qsma/utils/registry.py` | Phase 1 |
| **No persistent database** | No SQLite, no external DB — out of MVP scope | — | Never (MVP) |
| **No inter-run state** | Each `qsma scan` starts fresh unless `--cache` flag used | — | Phase 1 |

Cache key: `sha256` of sorted `(file_path, mtime)` pairs for the scanned tree.
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
| Full module specs, DAG, task allocation? | `PROJECT_CONTEXT.md §4–10` |
| What does module X do? | `PROJECT_CONTEXT.md §6.X` |
| What data does module X produce/consume? | `PROJECT_CONTEXT.md §7` + `src/qsma/utils/models.py` |
| What task to work on? | `PROJECT_CONTEXT.md §17–18` |
| What ADRs constrain me? | `PROJECT_CONTEXT.md §15` |
| Which branch is mine? | `PROJECT_CONTEXT.md §11` |
| What LLM provider is configured? | `.env` → `LLM_MODEL`, `LLM_BASE_URL` |
| What env vars are needed? | `.env.example` |
| How to write commit messages? | `PROMPT.md §7` (this file) |
| Can I change the DAG? | Yes — see `PROMPT.md §6` |
| Can I change `models.py`? | Yes, with PR + ADR — see `PROMPT.md §6` |
| Is there a database? | No — see `PROMPT.md §9` |
| Is there caching? | JSON cache on disk — see `PROMPT.md §9` |
| Where do session screenshots go? | `bob_sessions/<YourName>/` — see `PROMPT.md §4` |

---

*Keep this file and `PROJECT_CONTEXT.md` in sync.
If a rule here conflicts with `PROJECT_CONTEXT.md`, `PROJECT_CONTEXT.md` governs.*
