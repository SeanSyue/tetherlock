from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tetherlock
from conftest import public_pem, write_token
from tetherlock.access import AccessTokenError, TrustStore, verify_token_file


def _manifest(path: Path, entries: list[dict]) -> Path:
    path.write_text(json.dumps({"keys": entries}), encoding="utf-8")
    return path


def _entry(key_id: str, private_key: Ed25519PrivateKey, deprecated_at: str | None = None) -> dict:
    return {"key_id": key_id, "public_key_pem": public_pem(private_key).decode("ascii"), "deprecated_at": deprecated_at}


def test_manifest_trusts_several_keys_during_rotation(tmp_path, drive):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore.from_manifest(
        _manifest(tmp_path / "m.json", [_entry("new", new_key), _entry("old", old_key, "2099-01-01T00:00:00Z")])
    )
    assert {entry.key_id for entry in trust.active_keys()} == {"new", "old"}

    verify_token_file(write_token(drive, new_key, token_id="N"), trust=trust)
    verify_token_file(write_token(drive, old_key, token_id="O"), trust=trust)
    with pytest.raises(AccessTokenError):
        verify_token_file(write_token(drive, Ed25519PrivateKey.generate(), token_id="X"), trust=trust)


def test_key_past_its_deprecation_stops_verifying(tmp_path, drive):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore.from_manifest(
        _manifest(tmp_path / "m.json", [_entry("new", new_key), _entry("old", old_key, "2020-01-01T00:00:00Z")])
    )
    assert [entry.key_id for entry in trust.active_keys()] == ["new"]
    with pytest.raises(AccessTokenError, match="signature"):
        verify_token_file(write_token(drive, old_key), trust=trust)


def test_deprecation_is_evaluated_at_verification_time(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = TrustStore.from_manifest(_manifest(tmp_path / "m.json", [_entry("k", key, "2030-06-01T00:00:00Z")]))
    assert trust.active_keys(datetime(2030, 5, 31, tzinfo=timezone.utc))
    assert not trust.active_keys(datetime(2030, 6, 1, tzinfo=timezone.utc))


@pytest.mark.parametrize(
    "document",
    [
        {"keys": []},
        {"keys": [{"key_id": "broken"}]},
        {"keys": [{"key_id": "broken", "public_key_pem": "not a real pem"}]},
        {"keys": ["not an object"]},
        ["not", "an", "object"],
    ],
)
def test_malformed_manifests_are_rejected(tmp_path, document):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AccessTokenError):
        TrustStore.from_manifest(path)


def test_directory_prefers_manifest_over_single_key(tmp_path, drive):
    manifest_key, single_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    (tmp_path / "access_public_key.pem").write_bytes(public_pem(single_key))
    _manifest(tmp_path / "trusted_keys.json", [_entry("m", manifest_key)])

    trust = TrustStore.from_directory(tmp_path)
    verify_token_file(write_token(drive, manifest_key), trust=trust)
    with pytest.raises(AccessTokenError):
        verify_token_file(write_token(drive, single_key), trust=trust)


def test_directory_falls_back_to_single_key(tmp_path, drive):
    key = Ed25519PrivateKey.generate()
    (tmp_path / "access_public_key.pem").write_bytes(public_pem(key))
    verify_token_file(write_token(drive, key), trust=TrustStore.from_directory(tmp_path))


def test_empty_directory_gives_empty_store(tmp_path):
    assert TrustStore.from_directory(tmp_path).active_keys() == []


# ---------------------------------------------------------------------------
# Environment variables must not be able to change what is trusted.
# ---------------------------------------------------------------------------


def test_environment_cannot_inject_an_attacker_key(tmp_path, drive, trust, monkeypatch):
    """An attacker who can set user environment variables (no admin rights
    needed) points every plausible variable at their own key and manifest,
    then signs a token. It must still be rejected."""
    attacker = Ed25519PrivateKey.generate()
    attacker_pem = tmp_path / "attacker.pem"
    attacker_pem.write_bytes(public_pem(attacker))
    attacker_manifest = _manifest(tmp_path / "attacker_manifest.json", [_entry("evil", attacker)])

    for name in (
        "TETHERLOCK_ACCESS_PUBLIC_KEY",
        "TETHERLOCK_TRUSTED_KEYS_MANIFEST",
        "TETHERLOCK_TRUST_DIR",
        "ACCESS_PUBLIC_KEY",
        "TRUSTED_KEYS_MANIFEST",
    ):
        monkeypatch.setenv(name, str(attacker_manifest if "MANIFEST" in name else attacker_pem))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    (tmp_path / "trusted_keys.json").write_text(attacker_manifest.read_text(encoding="utf-8"), encoding="utf-8")

    token_path = write_token(drive, attacker)
    with pytest.raises(AccessTokenError, match="signature"):
        verify_token_file(token_path, trust=trust)


def test_trust_cannot_be_resolved_implicitly():
    """Every verification entry point requires an explicit trust store."""
    import inspect

    from tetherlock import access, maintenance, monitor

    for function in (access.verify_token_file, access.discover_verified_tokens, access.revalidate_token):
        parameter = inspect.signature(function).parameters["trust"]
        assert parameter.default is inspect.Parameter.empty, function.__name__
    for cls in (monitor.WorkspaceMonitor, maintenance.MaintenanceController):
        parameter = inspect.signature(cls.__init__).parameters["trust"]
        assert parameter.default is inspect.Parameter.empty, cls.__name__


def test_library_reads_no_environment_except_for_drive_scanning():
    """Static guard: the only environment access allowed in the package is
    the USER lookup used to find removable-media mount points on Linux."""
    package_dir = Path(tetherlock.__file__).parent
    offenders = []
    for source_file in sorted(package_dir.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            is_environ = isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv", "environb"}
            if not is_environ:
                continue
            offenders.append(f"{source_file.name}:{node.lineno}")
    assert offenders == ["access.py:" + str(_line_of_user_lookup(package_dir / "access.py"))], offenders


def _line_of_user_lookup(path: Path) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if 'os.environ.get("USER"' in line:
            return number
    raise AssertionError("USER lookup not found")


def test_extra_roots_are_the_only_non_mount_scan_locations(tmp_path, drive, trust, signing_key, monkeypatch):
    """Scanning locations cannot be added through the environment either."""
    from tetherlock.access import discover_verified_tokens

    write_token(drive, signing_key)
    for name in ("TETHERLOCK_ACCESS_TOKEN_ROOTS", "ACCESS_TOKEN_ROOTS"):
        monkeypatch.setenv(name, str(drive))
    assert drive not in [t.drive_root for t in discover_verified_tokens(trust=trust)]
    assert [t.drive_root for t in discover_verified_tokens(trust=trust, extra_roots=[drive])] == [drive]


@pytest.mark.parametrize("raw", [b"\xff\xfe not utf-8", b"[" * 50_000], ids=["invalid-utf8", "deep-nesting"])
def test_hostile_manifest_bytes_raise_access_token_error(tmp_path, raw):
    path = tmp_path / "trusted_keys.json"
    path.write_bytes(raw)
    with pytest.raises(AccessTokenError):
        TrustStore.from_manifest(path)
