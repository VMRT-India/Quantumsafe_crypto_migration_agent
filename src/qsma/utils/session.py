# qsma.utils.session — Redis session state manager
# Stub. Planned (Phase 2).
#
# Responsibilities:
#   get_session(session_id: str) -> MigrationSessionState | None
#   save_session(state: MigrationSessionState) -> None
#   delete_session(session_id: str) -> None
#
# Redis key:  qsma:session:<uuid4>
# TTL:        REDIS_SESSION_TTL_SECONDS (default 86400 = 24h)
# Fallback:   in-memory dict if Redis is unavailable (no resume capability)
# Config:     REDIS_URL env var (default redis://localhost:6379)
#
# See PROJECT_CONTEXT.md ADR-008.
