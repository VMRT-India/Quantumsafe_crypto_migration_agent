# qsma.advisor — Conversational CLI Advisor Agent
# Stub. Planned (Phase 2).
#
# Purpose:
#   A thin LLM-backed conversational layer that wraps the scan results and
#   lets the user interact in natural language BEFORE triggering the migration
#   pipeline.  The user never has to select menu options or remember finding IDs.
#
# What it does:
#   1. Receives the list[CryptoFinding] + DependencyGraph produced by the scan.
#   2. Starts an interactive REPL loop in the terminal (Rich-rendered).
#   3. Each user message is sent to LLMClient with a structured system prompt
#      that includes the full scan context (findings, risk scores, blast radii).
#   4. The LLM answers questions, explains findings, compares risk, and —
#      crucially — accepts natural-language instructions like:
#        "migrate everything CRITICAL except the auth module"
#        "show me what would change in crypto_utils.py"
#        "skip AES-128 for now, only fix RSA"
#   5. When the user confirms a migration intent, the advisor resolves it to a
#      concrete list[str] of finding IDs and returns them to the CLI for
#      handoff to the LangGraph MigrationGraph.
#   6. The user can also ask "what will break if I change auth/crypto.py?" and
#      the advisor answers using DependencyGraph.blast_radius() context.
#
# Entry point used by CLI:
#   qsma chat <path>   — scan first (or load cached scan), then enter advisor loop
#
# LangGraph node (optional — can also run as a simple loop without full graph):
#   advisor_node(state: MigrationSessionState) → MigrationSessionState
#   Sets state.selected_finding_ids based on conversation outcome.
#
# Key design rules:
#   - The advisor NEVER modifies source files. It only produces a finding selection.
#   - Conversation history is kept in-memory for the session only (not persisted).
#   - The LLM receives the scan context on every turn (or via a system prompt
#     prefix) so it always has full grounding.
#   - If the user types "quit" / "exit" / Ctrl-C, the session ends without migrating.
#   - The /migrate command (or equivalent natural language confirmation) hands off
#     to the MigrationGraph.
#
# See PROJECT_CONTEXT.md §6.10 and ADR-012.
