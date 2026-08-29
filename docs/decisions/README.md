# Architectural Decisions

Architectural Decision Records (ADRs) are documented in `PROJECT_CONTEXT.md` §14.

This directory is reserved for extended ADR documents when a decision is complex
enough to warrant its own file.

## Index

| ID | Title | Status |
|---|---|---|
| ADR-001 | Python-only MVP | Accepted |
| ADR-002 | Detection and classification are deterministic; all migration is LLM-agentic | Accepted |
| ADR-003 | libcst for safe file write after LLM-generated transform (not migration logic) | Accepted |
| ADR-004 | Shared models.py are frozen contracts | Accepted |
| ADR-005 | No web frontend in any phase | Accepted |
| ADR-006 | tree-sitter as primary multi-language parser | Accepted |
| ADR-007 | LangGraph for agentic orchestration of Planner → Migrator → Validator | Accepted |
| ADR-008 | Redis for session state persistence and mid-run resume | Accepted |
| ADR-009 | Agent training data stored in src/qsma/llm/training_data/ | Accepted |
| ADR-010 | Neo4j for intra-codebase dependency graph persistence (Detector Phase B) | Accepted |
| ADR-011 | Dual risk scoring in Classifier — deterministic algorithm score + LLM migration score | Accepted |
| ADR-012 | Advisor module — conversational LLM agent for finding selection (`qsma chat`) | Accepted |

Before making a significant architectural change, add an ADR entry to `PROJECT_CONTEXT.md`
and notify all team members.
