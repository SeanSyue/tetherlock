"""Delegated maintenance: temporary, capability-limited elevation.

Instead of handing out an administrator password, an administrator issues a
separate signed token (scope ``maintenance.v1``) listing exactly which
maintenance capabilities it grants. A colleague signed in with their own
account inserts the device and enters the token's password to open a
time-limited session.

The token uses the same signature, password verifier and device binding as
workspace tokens; only the scope differs. It does not mount a vault, so the
``vault_id`` field is a formality here.

The session's own expiry (minutes) is separate from the token's expiry
(usually much longer): when the session runs out, the password must be
entered again even if the token is still valid.

``active_session()`` re-checks the clock and re-verifies the token every
time it is called: the file must still be there, still carry a valid
signature from a key that is still trusted, still match this device, still be
unexpired, and still be byte-for-byte the payload the session was opened
with. A countdown shown in the UI is only a display; the check performed
right before each privileged operation is what actually enforces the limit.
Session state lives only in memory and is never written anywhere, so a
restart leaves nothing behind.

What a session must never be able to do (change the top-level owner
account, disable audit logging, re-sign its own token) is enforced by the
host application's own permission rules, not here. This module has no code
path that writes a token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from tetherlock.access import (
    AccessTokenError,
    TrustStore,
    VerifiedAccessToken,
    discover_verified_tokens,
    revalidate_token,
    unlock_verified_token,
    verify_token_file,
)

MAINTENANCE_SCOPE = "maintenance.v1"
DEFAULT_SESSION_MINUTES = 30

CAPABILITY_HEALTH_CHECK = "health_check"
CAPABILITY_BACKUP = "backup"
CAPABILITY_UNLOCK_USER = "unlock_user"
CAPABILITY_RESET_PASSWORD = "reset_password"
DEFAULT_CAPABILITIES = (
    CAPABILITY_HEALTH_CHECK,
    CAPABILITY_BACKUP,
    CAPABILITY_UNLOCK_USER,
    CAPABILITY_RESET_PASSWORD,
)


@dataclass(frozen=True)
class MaintenanceSession:
    token_id: str
    drive_root: Path
    token_path: Path
    allowed_capabilities: frozenset
    activated_at: datetime
    expires_at: datetime
    token: VerifiedAccessToken


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MaintenanceController:
    def __init__(
        self,
        *,
        trust: TrustStore,
        known_capabilities: Iterable[str] = DEFAULT_CAPABILITIES,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        """known_capabilities is the host's allow-list. A token may list other
        names, but only those the host actually implements are granted."""
        self._trust = trust
        self._known = frozenset(known_capabilities)
        self._clock = clock
        self._session: MaintenanceSession | None = None

    def discover_tokens(self, *, extra_roots: Iterable[Path] = ()) -> list[VerifiedAccessToken]:
        return discover_verified_tokens(
            trust=self._trust, expected_scope=MAINTENANCE_SCOPE, extra_roots=extra_roots
        )

    def activate(
        self,
        token: VerifiedAccessToken,
        password: str,
        *,
        duration_minutes: int = DEFAULT_SESSION_MINUTES,
    ) -> MaintenanceSession:
        """Open a session. A wrong password raises AccessTokenError, which
        the caller is expected to show to the user.

        The token is re-verified first: the device may have been swapped
        while the password was being typed, and maintenance should be no
        weaker than workspace unlocking in that respect.
        """
        # Only maintenance tokens open maintenance sessions. A workspace token
        # that happens to carry an allowed_capabilities field is refused.
        if token.scope != MAINTENANCE_SCOPE:
            raise AccessTokenError("Not a maintenance token.")
        token = revalidate_token(token, trust=self._trust)
        grant = unlock_verified_token(token, password)
        requested = token.payload.get("allowed_capabilities", [])
        if not isinstance(requested, list):
            requested = []
        capabilities = frozenset(item for item in requested if isinstance(item, str) and item in self._known)
        now = self._clock()
        self._session = MaintenanceSession(
            token_id=token.token_id,
            drive_root=grant.drive_root,
            token_path=grant.token_path,
            allowed_capabilities=capabilities,
            activated_at=now,
            expires_at=now + timedelta(minutes=duration_minutes),
            token=token,
        )
        return self._session

    def clear(self) -> None:
        self._session = None

    def active_session(self) -> MaintenanceSession | None:
        """The current session, or None. Expiry, removing the device, or any
        change that makes the token invalid or different ends the session
        here, at the moment of use."""
        session = self._session
        if session is None:
            return None
        try:
            valid = self._clock() < session.expires_at and self._token_unchanged(session)
        except Exception:
            self._session = None
            raise
        if not valid:
            self._session = None
            return None
        return session

    def _token_unchanged(self, session: MaintenanceSession) -> bool:
        try:
            current = verify_token_file(session.token_path, trust=self._trust, expected_scope=MAINTENANCE_SCOPE)
        except AccessTokenError:
            return False
        except Exception:
            # Fail closed on anything unexpected, then let the error surface.
            self._session = None
            raise
        return current.payload == session.token.payload

    def has_capability(self, capability: str) -> bool:
        session = self.active_session()
        return session is not None and capability in session.allowed_capabilities

    def remaining_seconds(self) -> int:
        session = self.active_session()
        if session is None:
            return 0
        return max(0, int((session.expires_at - self._clock()).total_seconds()))
