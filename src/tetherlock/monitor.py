"""Unlock-on-insert, lock-on-removal, independent of any UI toolkit.

The host calls ``WorkspaceMonitor.poll()`` on a timer (every two seconds
works well). Each poll does two things:

1. Checks that every unlocked scope still has its authorization device
   present and valid. Scopes whose device was removed, replaced, or whose
   token stopped verifying are locked individually; the others keep running.
2. Looks for newly inserted devices and walks the three gates:
   account permission (``is_authorized``), a validly signed token for the
   scope, then the scope's password. If the account is not authorized, no
   password prompt is ever shown.

Password prompts are the host's job (``prompt_password``). Many UI toolkits
implement modal dialogs with a nested event loop that keeps delivering timer
ticks, so ``poll()`` guards against re-entry: while one prompt is open no
second one can stack on top of it, and at most one new unlock is attempted
per tick.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from tetherlock.access import (
    AccessGrant,
    AccessTokenError,
    TrustStore,
    discover_verified_tokens,
    revalidate_token,
    unlock_verified_token,
    verify_token_file,
)

LOCK_DEVICE_REMOVED = "device_removed"
LOCK_NOT_AUTHORIZED = "not_authorized"
LOCK_REQUESTED = "requested"

DEFAULT_CANCEL_COOLDOWN = 60.0
DEFAULT_FAILURE_COOLDOWN = 20.0


@dataclass
class UnlockedScope:
    grant: AccessGrant
    handle: Any


class WorkspaceMonitor:
    def __init__(
        self,
        *,
        trust: TrustStore,
        scopes: Iterable[str],
        prompt_password: Callable[[str], str | None],
        on_unlock: Callable[[AccessGrant], Any],
        on_lock: Callable[[str, Any, str], None] | None = None,
        on_failure: Callable[[str, Exception], None] | None = None,
        is_authorized: Callable[[], bool] = lambda: True,
        extra_roots: Iterable[Path] = (),
        clock: Callable[[], float] = time.monotonic,
        cancel_cooldown: float = DEFAULT_CANCEL_COOLDOWN,
        failure_cooldown: float = DEFAULT_FAILURE_COOLDOWN,
    ) -> None:
        """
        prompt_password(scope) returns the entered password, or None if the
            user cancelled.
        on_unlock(grant) opens the protected area and returns a handle (for
            example a loaded plugin). If it raises, the attempt counts as a
            failure.
        on_lock(scope, handle, reason) tears the area down again.
        on_failure(scope, error) is told about wrong passwords, devices that
            changed during the prompt, and on_unlock errors.
        is_authorized() is the first gate: whether the signed-in account may
            open protected areas at all.
        """
        self._trust = trust
        self._scopes = tuple(scopes)
        self._prompt_password = prompt_password
        self._on_unlock = on_unlock
        self._on_lock = on_lock
        self._on_failure = on_failure
        self._is_authorized = is_authorized
        self._extra_roots = tuple(extra_roots)
        self._clock = clock
        self._cancel_cooldown = cancel_cooldown
        self._failure_cooldown = failure_cooldown

        self._unlocked: dict[str, UnlockedScope] = {}
        # Keyed by scope: when a device is detected there is no handle yet.
        self._last_token_id: dict[str, str] = {}
        self._retry_after: dict[str, float] = {}
        self._unlock_in_progress = False
        # Bumped by lock_all(); an open prompt from an older generation is stale.
        self._generation = 0

    # -- queries -----------------------------------------------------------

    def is_unlocked(self, scope: str) -> bool:
        return scope in self._unlocked

    def unlocked_scopes(self) -> list[str]:
        return list(self._unlocked)

    def handle(self, scope: str) -> Any:
        entry = self._unlocked.get(scope)
        return entry.handle if entry else None

    # -- polling -----------------------------------------------------------

    def poll(self) -> None:
        # Lock each scope on its own: removing one device must not close an
        # area whose device is still present. The check fails closed: if it
        # raises instead of answering, that scope is locked before the error
        # is passed on, and the remaining scopes are still checked.
        first_error: Exception | None = None
        for scope, entry in list(self._unlocked.items()):
            try:
                still_valid = self._device_still_valid(entry.grant)
            except Exception as exc:
                still_valid = False
                first_error = first_error or exc
            if not still_valid:
                try:
                    self.lock(scope, LOCK_DEVICE_REMOVED)
                except Exception as exc:
                    first_error = first_error or exc

        # Checked on every tick, before any discovery. An account without
        # permission never sees a password prompt, and anything that was
        # unlocked under a previous account is closed.
        allowed = False
        try:
            allowed = self._account_allowed()
            if not allowed:
                self.lock_all(LOCK_NOT_AUTHORIZED)
        except Exception as exc:
            first_error = first_error or exc
        # Report only after every revocation has been attempted. Never start
        # a new unlock on a tick whose checks or teardown did not finish cleanly.
        if first_error is not None:
            raise first_error
        if not allowed:
            return

        if self._unlock_in_progress:
            return

        for scope in self._scopes:
            if scope in self._unlocked:
                continue
            if self._try_unlock(scope):
                # At most one interactive unlock per tick, so two devices
                # inserted together do not open two prompts at once.
                break

    def _account_allowed(self) -> bool:
        try:
            return bool(self._is_authorized())
        except Exception:
            # A permission check that cannot answer is treated as "no".
            self.lock_all(LOCK_NOT_AUTHORIZED)
            raise

    def _device_still_valid(self, grant: AccessGrant) -> bool:
        if not grant.token_path.is_file() or not grant.drive_root.is_dir():
            return False
        try:
            current = verify_token_file(grant.token_path, trust=self._trust, expected_scope=grant.scope)
        except AccessTokenError:
            return False
        return current.token_id == grant.token_id

    def _try_unlock(self, scope: str) -> bool:
        """Return True if a password prompt was shown (whatever its outcome),
        False if no device was found or the scope is cooling down."""
        tokens = discover_verified_tokens(
            trust=self._trust, expected_scope=scope, extra_roots=self._extra_roots
        )
        if not tokens:
            self._last_token_id[scope] = ""
            self._retry_after[scope] = 0.0
            return False

        token = tokens[0]
        now = self._clock()
        if token.token_id == self._last_token_id.get(scope, "") and now < self._retry_after.get(scope, 0.0):
            return False

        self._unlock_in_progress = True
        self._last_token_id[scope] = token.token_id
        # The prompt can stay open for a long time, and the host may sign the
        # user out (lock_all) while it is showing. Remember which session the
        # prompt belongs to, so an answer typed into a stale prompt is thrown
        # away even if a different, authorized user has signed in since.
        generation = self._generation
        try:
            password = self._prompt_password(scope)
            if password is None:
                self._retry_after[scope] = now + self._cancel_cooldown
                return True

            if generation != self._generation or not self._account_allowed():
                self._forget(scope)
                if self._on_failure is not None:
                    self._on_failure(scope, AccessTokenError("The session changed while the password prompt was open."))
                return True

            try:
                revalidated = revalidate_token(token, trust=self._trust)
                grant = unlock_verified_token(revalidated, password)
                handle = self._on_unlock(grant)
            except Exception as exc:
                self._retry_after[scope] = now + self._failure_cooldown
                if self._on_failure is not None:
                    self._on_failure(scope, exc)
                return True

            if generation != self._generation:
                # lock_all() ran while the host was opening the area.
                if self._on_lock is not None:
                    self._on_lock(scope, handle, LOCK_REQUESTED)
                return True
            self._unlocked[scope] = UnlockedScope(grant=grant, handle=handle)
        finally:
            self._unlock_in_progress = False
        return True

    def _forget(self, scope: str) -> None:
        self._last_token_id.pop(scope, None)
        self._retry_after.pop(scope, None)

    # -- locking -----------------------------------------------------------

    def lock(self, scope: str, reason: str = LOCK_REQUESTED) -> None:
        entry = self._unlocked.pop(scope, None)
        if entry is None:
            return
        # Reset detection state for this scope only. Cooldowns exist for
        # repeated failures, not for a clean removal, so re-inserting the same
        # device is picked up again straight away.
        self._forget(scope)
        if self._on_lock is not None:
            self._on_lock(scope, entry.handle, reason)

    def lock_all(self, reason: str = LOCK_REQUESTED) -> None:
        """Call on sign-out and on application exit: on a shared machine,
        every area the previous user opened has to close with them. A failing
        on_lock does not stop the remaining scopes from being locked. Any
        password prompt that is still open is invalidated as well."""
        self._generation += 1
        first_error: Exception | None = None
        for scope in list(self._unlocked):
            try:
                self.lock(scope, reason)
            except Exception as exc:
                first_error = first_error or exc
        if first_error is not None:
            raise first_error
