"""
qsma.utils.session — session state manager

In-memory implementation for this session (no Redis available in this
environment). Same signatures as the Redis design (ADR-008) so swapping in a
real RedisSaver-backed implementation later is a drop-in change:

    get_session(session_id: str) -> MigrationSessionState | None
    save_session(state: MigrationSessionState) -> None
    delete_session(session_id: str) -> None

Resume (`qsma migrate --resume <session_id>`) works within a single running
process; it does not survive a process restart without real Redis.
"""

from __future__ import annotations

from qsma.utils.models import MigrationSessionState

_SESSIONS: dict[str, MigrationSessionState] = {}


def get_session(session_id: str) -> MigrationSessionState | None:
    return _SESSIONS.get(session_id)


def save_session(state: MigrationSessionState) -> None:
    _SESSIONS[state.session_id] = state


def delete_session(session_id: str) -> None:
    _SESSIONS.pop(session_id, None)
