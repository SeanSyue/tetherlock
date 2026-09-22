"""Runs the README quick-start through the CLI entry point."""

from __future__ import annotations

import json

import pytest

from tetherlock import cli
from tetherlock.access import TrustStore, discover_verified_tokens, unlock_verified_token

KEY_PASSWORD = "offline key password"
WORKSPACE_PASSWORD = "workspace password 01"


class Answers:
    def __init__(self, monkeypatch):
        self.queue: list[str] = []
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": self.queue.pop(0))


@pytest.fixture
def answers(monkeypatch):
    return Answers(monkeypatch)


def test_quick_start(tmp_path, drive, answers, capsys):
    keys, trust_dir = tmp_path / "keys", tmp_path / "trust"

    answers.queue = [KEY_PASSWORD, KEY_PASSWORD]
    assert cli.main(["init-keys", "--output-dir", str(keys)]) == 0
    assert b"ENCRYPTED" in (keys / "access_private_key.pem").read_bytes()

    assert cli.main(["add-trusted-key", "--trust-dir", str(trust_dir), "--key-id", "k1",
                     "--public-key", str(keys / "access_public_key.pem")]) == 0

    answers.queue = [KEY_PASSWORD, WORKSPACE_PASSWORD, WORKSPACE_PASSWORD]
    assert cli.main(["issue-token", "--private-key", str(keys / "access_private_key.pem"),
                     "--drive-root", str(drive)]) == 0

    answers.queue = [WORKSPACE_PASSWORD]
    assert cli.main(["verify-token", "--trust-dir", str(trust_dir), "--drive-root", str(drive),
                     "--check-password"]) == 0
    assert "Password accepted" in capsys.readouterr().out

    tokens = discover_verified_tokens(trust=TrustStore.from_directory(trust_dir), extra_roots=[drive])
    assert len(tokens) == 1
    unlock_verified_token(tokens[0], WORKSPACE_PASSWORD)


def test_private_key_password_is_mandatory(tmp_path, answers, capsys):
    answers.queue = ["", ""]
    assert cli.main(["init-keys", "--output-dir", str(tmp_path / "keys")]) == 1
    assert "required" in capsys.readouterr().err
    assert not (tmp_path / "keys" / "access_private_key.pem").exists()


def test_short_workspace_password_is_refused(tmp_path, drive, answers):
    keys = tmp_path / "keys"
    answers.queue = [KEY_PASSWORD, KEY_PASSWORD]
    cli.main(["init-keys", "--output-dir", str(keys)])
    answers.queue = [KEY_PASSWORD, "short", "short"]
    assert cli.main(["issue-token", "--private-key", str(keys / "access_private_key.pem"),
                     "--drive-root", str(drive)]) == 1
    assert list(drive.iterdir()) == []


def test_existing_token_is_not_overwritten(tmp_path, drive, answers):
    keys = tmp_path / "keys"
    answers.queue = [KEY_PASSWORD, KEY_PASSWORD]
    cli.main(["init-keys", "--output-dir", str(keys)])
    args = ["issue-token", "--private-key", str(keys / "access_private_key.pem"), "--drive-root", str(drive)]
    answers.queue = [KEY_PASSWORD, WORKSPACE_PASSWORD, WORKSPACE_PASSWORD]
    assert cli.main(args) == 0
    before = next(drive.iterdir()).read_text(encoding="utf-8")
    assert cli.main(args) == 1
    assert next(drive.iterdir()).read_text(encoding="utf-8") == before


def test_maintenance_capabilities_are_signed_into_token(tmp_path, drive, answers):
    keys = tmp_path / "keys"
    answers.queue = [KEY_PASSWORD, KEY_PASSWORD]
    cli.main(["init-keys", "--output-dir", str(keys)])
    answers.queue = [KEY_PASSWORD, WORKSPACE_PASSWORD, WORKSPACE_PASSWORD]
    assert cli.main(["issue-token", "--private-key", str(keys / "access_private_key.pem"),
                     "--drive-root", str(drive), "--scope", "maintenance.v1",
                     "--allowed-capabilities", "health_check, backup"]) == 0
    document = json.loads(next(drive.iterdir()).read_text(encoding="utf-8"))
    assert document["payload"]["allowed_capabilities"] == ["health_check", "backup"]


def test_deprecate_and_list(tmp_path, answers, capsys):
    keys, trust_dir = tmp_path / "keys", tmp_path / "trust"
    answers.queue = [KEY_PASSWORD, KEY_PASSWORD]
    cli.main(["init-keys", "--output-dir", str(keys)])
    cli.main(["add-trusted-key", "--trust-dir", str(trust_dir), "--key-id", "k1",
              "--public-key", str(keys / "access_public_key.pem")])
    assert cli.main(["deprecate-trusted-key", "--trust-dir", str(trust_dir), "--key-id", "k1",
                     "--deprecated-at", "not a date"]) == 1
    assert cli.main(["deprecate-trusted-key", "--trust-dir", str(trust_dir), "--key-id", "k1",
                     "--deprecated-at", "2020-01-01T00:00:00Z"]) == 0
    capsys.readouterr()
    cli.main(["list-trusted-keys", "--trust-dir", str(trust_dir)])
    assert "k1: deprecated at 2020-01-01T00:00:00Z" in capsys.readouterr().out
    assert TrustStore.from_directory(trust_dir).active_keys() == []
