from __future__ import annotations

import shutil

import pytest

from conftest import PASSWORD, write_token
from tetherlock.access import DEFAULT_SCOPE, AccessTokenError
from tetherlock.monitor import (
    LOCK_DEVICE_REMOVED,
    LOCK_NOT_AUTHORIZED,
    LOCK_REQUESTED,
    WorkspaceMonitor,
)


class Harness:
    """Drives a WorkspaceMonitor with a fake clock and scripted prompts."""

    def __init__(self, trust, roots, scopes=(DEFAULT_SCOPE,)):
        self.now = 1000.0
        self.answers: list[str | None] = []
        self.prompts: list[str] = []
        self.unlocked: list[str] = []
        self.locked: list[tuple[str, str]] = []
        self.failures: list[tuple[str, Exception]] = []
        self.authorized = True
        self.unlock_error: Exception | None = None
        self.on_prompt = None
        self.monitor = WorkspaceMonitor(
            trust=trust,
            scopes=scopes,
            prompt_password=self._prompt,
            on_unlock=self._unlock,
            on_lock=lambda scope, handle, reason: self.locked.append((scope, reason)),
            on_failure=lambda scope, exc: self.failures.append((scope, exc)),
            is_authorized=lambda: self.authorized,
            extra_roots=roots,
            clock=lambda: self.now,
        )

    def _prompt(self, scope):
        self.prompts.append(scope)
        if self.on_prompt is not None:
            self.on_prompt()
        return self.answers.pop(0) if self.answers else None

    def _unlock(self, grant):
        if self.unlock_error is not None:
            raise self.unlock_error
        self.unlocked.append(grant.scope)
        return f"handle:{grant.scope}"


def test_no_device_means_no_prompt(trust, drive):
    h = Harness(trust, [drive])
    h.monitor.poll()
    assert h.prompts == [] and not h.monitor.is_unlocked(DEFAULT_SCOPE)


def test_insert_device_and_enter_password_unlocks(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    assert h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.monitor.handle(DEFAULT_SCOPE) == f"handle:{DEFAULT_SCOPE}"


def test_removing_device_locks_on_next_poll(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    shutil.rmtree(drive)
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.locked == [(DEFAULT_SCOPE, LOCK_DEVICE_REMOVED)]


def test_replacing_token_on_device_locks(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    write_token(drive, signing_key, token_id="SOMEONE-ELSE")
    h.monitor.poll()
    assert (DEFAULT_SCOPE, LOCK_DEVICE_REMOVED) in h.locked


def test_unauthorized_account_never_sees_a_prompt(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.authorized = False
    h.monitor.poll()
    assert h.prompts == []


def test_losing_authorization_locks_everything(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    h.authorized = False
    h.monitor.poll()
    assert h.locked == [(DEFAULT_SCOPE, LOCK_NOT_AUTHORIZED)]


def test_cancel_waits_for_cooldown_before_asking_again(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [None]
    h.monitor.poll()
    h.now += 59
    h.monitor.poll()
    assert len(h.prompts) == 1
    h.now += 2
    h.monitor.poll()
    assert len(h.prompts) == 2


def test_wrong_password_has_shorter_cooldown_and_reports_failure(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = ["wrong password"]
    h.monitor.poll()
    assert isinstance(h.failures[0][1], AccessTokenError)
    h.now += 19
    h.monitor.poll()
    assert len(h.prompts) == 1
    h.answers = [PASSWORD]
    h.now += 2
    h.monitor.poll()
    assert h.monitor.is_unlocked(DEFAULT_SCOPE)


def test_reinserting_after_clean_removal_skips_cooldown(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    token_file = next(drive.iterdir())
    saved = token_file.read_bytes()
    token_file.unlink()
    h.monitor.poll()
    token_file.write_bytes(saved)
    h.answers = [PASSWORD]
    h.monitor.poll()
    assert len(h.prompts) == 2 and h.monitor.is_unlocked(DEFAULT_SCOPE)


def test_device_removed_while_typing_password_does_not_unlock(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.on_prompt = lambda: shutil.rmtree(drive)
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.unlocked == []
    assert "unavailable" in str(h.failures[0][1])


def test_device_swapped_while_typing_password_does_not_unlock(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.on_prompt = lambda: write_token(drive, signing_key, token_id="SWAPPED", vault_id="OTHER")
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.unlocked == []


def test_poll_during_open_prompt_does_not_stack_a_second_prompt(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.on_prompt = h.monitor.poll  # a nested event loop delivering a timer tick
    h.monitor.poll()
    assert h.prompts == [DEFAULT_SCOPE]
    assert h.monitor.is_unlocked(DEFAULT_SCOPE)


def test_one_new_unlock_per_tick(trust, drive, signing_key):
    write_token(drive, signing_key, token_id="A", scope="alpha.v1")
    write_token(drive, signing_key, token_id="B", scope="beta.v1")
    h = Harness(trust, [drive], scopes=("alpha.v1", "beta.v1"))
    h.answers = [PASSWORD, PASSWORD]
    h.monitor.poll()
    assert h.prompts == ["alpha.v1"]
    h.monitor.poll()
    assert h.prompts == ["alpha.v1", "beta.v1"]
    assert sorted(h.monitor.unlocked_scopes()) == ["alpha.v1", "beta.v1"]


def test_removing_one_device_leaves_other_scope_unlocked(trust, tmp_path, signing_key):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    write_token(first, signing_key, token_id="A", scope="alpha.v1")
    write_token(second, signing_key, token_id="B", scope="beta.v1")
    h = Harness(trust, [first, second], scopes=("alpha.v1", "beta.v1"))
    h.answers = [PASSWORD, PASSWORD]
    h.monitor.poll()
    h.monitor.poll()
    shutil.rmtree(first)
    h.monitor.poll()
    assert h.monitor.unlocked_scopes() == ["beta.v1"]


def test_on_unlock_error_counts_as_failure(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.unlock_error = RuntimeError("module failed to load")
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.failures and h.failures[0][1] is h.unlock_error


def test_lock_all_closes_every_scope_even_if_one_teardown_fails(trust, drive, signing_key):
    write_token(drive, signing_key, token_id="A", scope="alpha.v1")
    write_token(drive, signing_key, token_id="B", scope="beta.v1")
    h = Harness(trust, [drive], scopes=("alpha.v1", "beta.v1"))
    h.answers = [PASSWORD, PASSWORD]
    h.monitor.poll()
    h.monitor.poll()

    calls = []

    def failing_on_lock(scope, handle, reason):
        calls.append(scope)
        if scope == "alpha.v1":
            raise RuntimeError("teardown failed")

    h.monitor._on_lock = failing_on_lock
    with pytest.raises(RuntimeError):
        h.monitor.lock_all(LOCK_REQUESTED)
    assert sorted(calls) == ["alpha.v1", "beta.v1"]
    assert h.monitor.unlocked_scopes() == []


# ---------------------------------------------------------------------------
# Fail closed: a token that turns into garbage, or a check that errors, locks.
# ---------------------------------------------------------------------------


def _unlocked_harness(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.monitor.poll()
    assert h.monitor.is_unlocked(DEFAULT_SCOPE)
    return h


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe not utf-8", b'{"payload": {"a": "\\ud800"}, "signature": "AAAA"}'],
    ids=["invalid-utf8", "lone-surrogate"],
)
def test_token_turned_into_garbage_locks_without_raising(trust, drive, signing_key, raw):
    h = _unlocked_harness(trust, drive, signing_key)
    next(drive.iterdir()).write_bytes(raw)
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.locked == [(DEFAULT_SCOPE, LOCK_DEVICE_REMOVED)]


def test_unexpected_error_in_device_check_locks_before_raising(trust, drive, signing_key, monkeypatch):
    h = _unlocked_harness(trust, drive, signing_key)

    def broken(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("tetherlock.monitor.verify_token_file", broken)
    with pytest.raises(RuntimeError):
        h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)


def test_authorization_check_that_raises_locks_everything(trust, drive, signing_key):
    h = _unlocked_harness(trust, drive, signing_key)

    def broken():
        raise RuntimeError("permission service down")

    h.monitor._is_authorized = broken
    with pytest.raises(RuntimeError):
        h.monitor.poll()
    assert h.monitor.unlocked_scopes() == []


# ---------------------------------------------------------------------------
# A password typed into a prompt that outlived its session must not unlock.
# ---------------------------------------------------------------------------


def test_sign_out_during_prompt_discards_the_password(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]

    def sign_out():
        h.authorized = False
        h.monitor.lock_all()

    h.on_prompt = sign_out
    h.monitor.poll()
    assert h.unlocked == []
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert "session changed" in str(h.failures[0][1])


def test_user_switch_during_prompt_discards_the_password(trust, drive, signing_key):
    """The next user is also allowed in, so re-checking is_authorized() alone
    would not catch this; the session generation does."""
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.on_prompt = h.monitor.lock_all
    h.monitor.poll()
    assert h.unlocked == []

    # The new user is asked afresh on the next tick, with no cooldown.
    h.on_prompt = None
    h.answers = [PASSWORD]
    h.monitor.poll()
    assert h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert len(h.prompts) == 2


def test_losing_authorization_during_prompt_discards_the_password(trust, drive, signing_key):
    """Even if the host forgets to call lock_all(), eligibility is re-checked
    after the prompt."""
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    h.on_prompt = lambda: setattr(h, "authorized", False)
    h.monitor.poll()
    assert h.unlocked == []


def test_lock_all_while_host_is_opening_closes_it_again(trust, drive, signing_key):
    write_token(drive, signing_key)
    h = Harness(trust, [drive])
    h.answers = [PASSWORD]
    original_unlock = h.monitor._on_unlock

    def unlock_then_sign_out(grant):
        handle = original_unlock(grant)
        h.monitor.lock_all()
        return handle

    h.monitor._on_unlock = unlock_then_sign_out
    h.monitor.poll()
    assert not h.monitor.is_unlocked(DEFAULT_SCOPE)
    assert h.locked == [(DEFAULT_SCOPE, LOCK_REQUESTED)]


def test_poll_attempts_all_revocations_when_one_teardown_raises(trust, drive, signing_key):
    for scope in ("alpha.v1", "beta.v1"):
        write_token(drive, signing_key, scope=scope)
    h = Harness(trust, [drive], scopes=("alpha.v1", "beta.v1"))
    h.answers = [PASSWORD, PASSWORD]
    h.monitor.poll()
    h.monitor.poll()
    calls = []

    def close(scope, handle, reason):
        calls.append(scope)
        if scope == "alpha.v1":
            raise RuntimeError("first teardown failed")

    h.monitor._on_lock = close
    for token in drive.glob("*.json"):
        token.write_bytes(b"\xff")
    with pytest.raises(RuntimeError, match="first teardown"):
        h.monitor.poll()
    assert calls == ["alpha.v1", "beta.v1"]
    assert h.monitor.unlocked_scopes() == []


def test_device_error_does_not_skip_account_revocation(trust, drive, signing_key, monkeypatch):
    for scope in ("alpha.v1", "beta.v1"):
        write_token(drive, signing_key, scope=scope)
    h = Harness(trust, [drive], scopes=("alpha.v1", "beta.v1"))
    h.answers = [PASSWORD, PASSWORD]
    h.monitor.poll()
    h.monitor.poll()
    h.authorized = False
    original = h.monitor._device_still_valid

    def check(grant):
        if grant.scope == "alpha.v1":
            raise RuntimeError("device check failed")
        return original(grant)

    monkeypatch.setattr(h.monitor, "_device_still_valid", check)
    with pytest.raises(RuntimeError, match="device check"):
        h.monitor.poll()
    assert h.monitor.unlocked_scopes() == []
    assert [scope for scope, reason in h.locked] == ["alpha.v1", "beta.v1"]
