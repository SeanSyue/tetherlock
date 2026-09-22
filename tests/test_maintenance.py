from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import write_token
from tetherlock.access import AccessTokenError, verify_token_file
from tetherlock.maintenance import (
    CAPABILITY_BACKUP,
    CAPABILITY_HEALTH_CHECK,
    CAPABILITY_RESET_PASSWORD,
    CAPABILITY_UNLOCK_USER,
    MAINTENANCE_SCOPE,
    MaintenanceController,
)

MAINT_PASSWORD = "maintenance-passphrase-01"


class Clock:
    def __init__(self):
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def _issue(drive, key, capabilities):
    return write_token(
        drive,
        key,
        token_id="MAINT-001",
        scope=MAINTENANCE_SCOPE,
        vault_id="MAINT",
        password=MAINT_PASSWORD,
        extra_payload={"allowed_capabilities": list(capabilities)},
    )


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def controller(trust, clock):
    return MaintenanceController(trust=trust, clock=clock)


def test_wrong_password_does_not_open_a_session(controller, trust, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    with pytest.raises(AccessTokenError):
        controller.activate(token, "wrong password")
    assert controller.active_session() is None


def test_only_known_capabilities_are_granted(controller, trust, drive, signing_key):
    requested = [CAPABILITY_HEALTH_CHECK, CAPABILITY_BACKUP, CAPABILITY_UNLOCK_USER, CAPABILITY_RESET_PASSWORD, "grant_root"]
    token = verify_token_file(_issue(drive, signing_key, requested), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    session = controller.activate(token, MAINT_PASSWORD)
    assert session.allowed_capabilities == frozenset(requested[:4])
    assert not controller.has_capability("grant_root")


def test_host_allow_list_limits_capabilities(trust, clock, drive, signing_key):
    controller = MaintenanceController(trust=trust, clock=clock, known_capabilities=[CAPABILITY_HEALTH_CHECK])
    token = verify_token_file(
        _issue(drive, signing_key, [CAPABILITY_HEALTH_CHECK, CAPABILITY_BACKUP]),
        trust=trust,
        expected_scope=MAINTENANCE_SCOPE,
    )
    controller.activate(token, MAINT_PASSWORD)
    assert controller.has_capability(CAPABILITY_HEALTH_CHECK)
    assert not controller.has_capability(CAPABILITY_BACKUP)


def test_session_expires(controller, trust, clock, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    controller.activate(token, MAINT_PASSWORD, duration_minutes=30)
    clock.now += timedelta(minutes=29)
    assert controller.has_capability(CAPABILITY_BACKUP)
    assert controller.remaining_seconds() == 60
    clock.now += timedelta(minutes=1)
    assert controller.active_session() is None
    assert controller.remaining_seconds() == 0


def test_removing_device_ends_session_immediately(controller, trust, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    controller.activate(token, MAINT_PASSWORD)
    shutil.rmtree(drive)
    assert not controller.has_capability(CAPABILITY_BACKUP)
    assert controller.active_session() is None


def test_clear_ends_session(controller, trust, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    controller.activate(token, MAINT_PASSWORD)
    controller.clear()
    assert controller.active_session() is None


def test_device_swapped_before_activation_is_rejected(controller, trust, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    write_token(drive, signing_key, token_id="OTHER", scope=MAINTENANCE_SCOPE, vault_id="MAINT", password=MAINT_PASSWORD)
    with pytest.raises(AccessTokenError):
        controller.activate(token, MAINT_PASSWORD)
    assert controller.active_session() is None


def test_discovery_finds_only_maintenance_scope(controller, drive, signing_key):
    _issue(drive, signing_key, ["backup"])
    write_token(drive, signing_key, token_id="WORKSPACE")
    found = controller.discover_tokens(extra_roots=[drive])
    assert [t.token_id for t in found] == ["MAINT-001"]


def test_workspace_token_cannot_open_maintenance(controller, trust, drive, signing_key):
    token_path = write_token(drive, signing_key)
    with pytest.raises(AccessTokenError, match="scope"):
        verify_token_file(token_path, trust=trust, expected_scope=MAINTENANCE_SCOPE)


# ---------------------------------------------------------------------------
# The session is re-verified on every use, not just checked for existence.
# ---------------------------------------------------------------------------


def _active(controller, trust, drive, signing_key):
    token = verify_token_file(_issue(drive, signing_key, ["backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE)
    controller.activate(token, MAINT_PASSWORD)
    assert controller.has_capability(CAPABILITY_BACKUP)
    return token.token_path


@pytest.mark.parametrize("raw", [b"garbage", b"\xff\xfe not utf-8", b""], ids=["text", "invalid-utf8", "empty"])
def test_token_content_destroyed_ends_session(controller, trust, drive, signing_key, raw):
    token_path = _active(controller, trust, drive, signing_key)
    token_path.write_bytes(raw)
    assert not controller.has_capability(CAPABILITY_BACKUP)
    assert controller.active_session() is None


def test_token_replaced_by_another_valid_token_ends_session(controller, trust, drive, signing_key):
    _active(controller, trust, drive, signing_key)
    write_token(
        drive, signing_key, token_id="MAINT-002", scope=MAINTENANCE_SCOPE, vault_id="MAINT",
        password=MAINT_PASSWORD, extra_payload={"allowed_capabilities": ["backup"]},
    )
    assert not controller.has_capability(CAPABILITY_BACKUP)


def test_token_resigned_by_untrusted_key_ends_session(controller, trust, drive, signing_key):
    _active(controller, trust, drive, signing_key)
    _issue(drive, Ed25519PrivateKey.generate(), ["backup"])  # same token_id, untrusted signer
    assert not controller.has_capability(CAPABILITY_BACKUP)


def test_workspace_token_with_capabilities_cannot_open_maintenance(controller, trust, drive, signing_key):
    token_path = write_token(
        drive, signing_key, password=MAINT_PASSWORD, extra_payload={"allowed_capabilities": ["backup"]}
    )
    workspace_token = verify_token_file(token_path, trust=trust)
    with pytest.raises(AccessTokenError, match="maintenance"):
        controller.activate(workspace_token, MAINT_PASSWORD)
    assert controller.active_session() is None


def test_non_string_capabilities_are_ignored(controller, trust, drive, signing_key):
    token = verify_token_file(
        _issue(drive, signing_key, [{"x": 1}, ["backup"], "backup"]), trust=trust, expected_scope=MAINTENANCE_SCOPE
    )
    session = controller.activate(token, MAINT_PASSWORD)
    assert session.allowed_capabilities == frozenset({"backup"})


def test_clock_error_clears_session_before_raising(controller, trust, drive, signing_key, monkeypatch):
    _active(controller, trust, drive, signing_key)
    original = controller._clock

    def broken_clock():
        raise RuntimeError("clock unavailable")

    monkeypatch.setattr(controller, "_clock", broken_clock)
    with pytest.raises(RuntimeError, match="clock unavailable"):
        controller.has_capability(CAPABILITY_BACKUP)
    monkeypatch.setattr(controller, "_clock", original)
    assert controller.active_session() is None
