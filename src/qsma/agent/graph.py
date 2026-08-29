# qsma.agent.graph — LangGraph StateGraph wiring
# Stub. Planned (Phase 2).
#
# Architecture:
#   planner_node  — LLM agent: reads CryptoFinding + few-shot → produces MigrationPlan
#   migrator_node — LLM agent: reads MigrationPlan + original code → produces transformed code fragment;
#                              uses libcst patcher to write result into source file
#   validator_node — LLM agent: syntax check + test run + LLM failure analysis → retry_hints or pass
#
# Conditional edges:
#   validator_node pass      → END (→ Reporter)
#   validator_node retry     → migrator_node  (attempt < 3)
#   validator_node escalate  → END (MigrationStatus.MANUAL_REQUIRED)
#
# State:       MigrationSessionState  (src/qsma/utils/models.py)
# Checkpointer: RedisSaver (langgraph-checkpoint-redis)
#
# See PROJECT_CONTEXT.md ADR-007 and ADR-008.
