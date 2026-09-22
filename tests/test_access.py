from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import PASSWORD, write_token
from tetherlock.access import (
    DEFAULT_SCOPE,
    DEFAULT_VAULT_DIRNAME,
    AccessTokenError,
    TrustStore,
    _canonical_payload,
    discover_verified_tokens,
    revalidate_token,
    token_filename_for_scope,
    unlock_verified_token,
    verify_token_file,
)


def test_signed_token_verifies_and_unlocks(drive, signing_key, trust):
    token_path = write_token(drive, signing_key)
    token = verify_token_file(token_path, trust=trust)
    grant = unlock_verified_token(token, PASSWORD)
    assert grant.vault_root == drive / DEFAULT_VAULT_DIRNAME / "VAULT-001"


def test_wrong_password_is_rejected(drive, signing_key, trust):
    token = verify_token_file(write_token(drive, signing_key), trust=trust)
    with pytest.raises(AccessTokenError):
        unlock_verified_token(token, "wrong password")
    with pytest.raises(AccessTokenError):
        unlock_verified_token(token, "")


def test_token_does_not_contain_the_password(drive, signing_key):
    token_path = write_token(drive, signing_key)
    assert PASSWORD not in token_path.read_text(encoding="utf-8")


def test_payload_tampering_breaks_the_signature(drive, signing_key, trust):
    token_path = write_token(drive, signing_key)
    document = json.loads(token_path.read_text(encoding="utf-8"))
    document["payload"]["vault_id"] = "CHANGED"
    token_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AccessTokenError, match="signature"):
        verify_token_file(token_path, trust=trust)


def test_token_signed_by_untrusted_key_is_rejected(drive, trust):
    token_path = write_token(drive, Ed25519PrivateKey.generate())
    with pytest.raises(AccessTokenError, match="signature"):
        verify_token_file(token_path, trust=trust)


def test_empty_trust_store_rejects_everything(drive, signing_key):
    token_path = write_token(drive, signing_key)
    with pytest.raises(AccessTokenError, match="No trusted"):
        verify_token_file(token_path, trust=TrustStore())


def test_scope_mismatch_is_rejected(drive, signing_key, trust):
    token_path = write_token(drive, signing_key, scope="other.scope.v1")
    with pytest.raises(AccessTokenError, match="scope"):
        verify_token_file(token_path, trust=trust, expected_scope=DEFAULT_SCOPE)


def test_expired_token_is_rejected(drive, signing_key, trust):
    token_path = write_token(drive, signing_key, expires_at="2020-01-01T00:00:00+00:00")
    with pytest.raises(AccessTokenError, match="expired"):
        verify_token_file(token_path, trust=trust)


def test_token_bound_to_another_device_is_rejected(drive, signing_key, trust):
    token_path = write_token(drive, signing_key, drive_serial="DEADBEEF")
    with pytest.raises(AccessTokenError, match="different storage device"):
        verify_token_file(token_path, trust=trust)


def test_unbound_token_verifies_anywhere(drive, signing_key, trust):
    token_path = write_token(drive, signing_key, drive_serial="ANY")
    assert verify_token_file(token_path, trust=trust).drive_serial == "ANY"


@pytest.mark.parametrize(
    "bad_vault_id",
    [".", "..", "../vault", "..\\vault", "C:\\vault", "/vault", "vault/sub", "vault\\sub", ""],
)
def test_unsafe_vault_ids_are_rejected(drive, signing_key, trust, bad_vault_id):
    token_path = write_token(drive, signing_key, vault_id=bad_vault_id)
    with pytest.raises(AccessTokenError):
        verify_token_file(token_path, trust=trust)


@pytest.mark.parametrize("bad_dirname", ["", ".", "..", "a/b", "a\\b"])
def test_unsafe_vault_dirnames_are_rejected(drive, signing_key, trust, bad_dirname):
    token_path = write_token(drive, signing_key, vault_dirname=bad_dirname)
    with pytest.raises(AccessTokenError, match="vault directory"):
        verify_token_file(token_path, trust=trust)


def test_weak_scrypt_parameters_are_refused(drive, signing_key, trust):
    """A validly signed token that asks for a cheap KDF must still be refused,
    otherwise offline guessing of the password would become cheap."""
    token_path = write_token(drive, signing_key)
    document = json.loads(token_path.read_text(encoding="utf-8"))
    document["payload"]["password_kdf"]["n"] = 2**10
    document["signature"] = base64.urlsafe_b64encode(
        signing_key.sign(_canonical_payload(document["payload"]))
    ).decode("ascii")
    token_path.write_text(json.dumps(document), encoding="utf-8")

    token = verify_token_file(token_path, trust=trust)
    with pytest.raises(AccessTokenError, match="minimum policy"):
        unlock_verified_token(token, PASSWORD)


@pytest.mark.parametrize("bad_scope", ["", "../x", "a/b", "a b", "x" * 65])
def test_scope_is_validated_before_becoming_a_filename(bad_scope):
    with pytest.raises(AccessTokenError):
        token_filename_for_scope(bad_scope)


def test_two_scopes_share_a_drive_with_independent_passwords(drive, signing_key, trust):
    write_token(drive, signing_key, token_id="A", scope="alpha.v1", password="alpha password 1")
    write_token(drive, signing_key, token_id="B", scope="beta.v1", password="beta password 22")
    assert token_filename_for_scope("alpha.v1") != token_filename_for_scope("beta.v1")

    alpha = discover_verified_tokens(trust=trust, expected_scope="alpha.v1", extra_roots=[drive])
    beta = discover_verified_tokens(trust=trust, expected_scope="beta.v1", extra_roots=[drive])
    assert [t.token_id for t in alpha] == ["A"]
    assert [t.token_id for t in beta] == ["B"]

    unlock_verified_token(alpha[0], "alpha password 1")
    unlock_verified_token(beta[0], "beta password 22")
    with pytest.raises(AccessTokenError):
        unlock_verified_token(alpha[0], "beta password 22")
    with pytest.raises(AccessTokenError):
        unlock_verified_token(beta[0], "alpha password 1")


def test_discovery_silently_skips_invalid_tokens(drive, trust):
    write_token(drive, Ed25519PrivateKey.generate())
    (drive.parent / "garbage").mkdir()
    (drive.parent / "garbage" / token_filename_for_scope(DEFAULT_SCOPE)).write_text("not json", encoding="utf-8")
    assert discover_verified_tokens(trust=trust, extra_roots=[drive, drive.parent / "garbage"]) == []


def test_revalidation_passes_when_nothing_changed(drive, signing_key, trust):
    original = verify_token_file(write_token(drive, signing_key), trust=trust)
    assert revalidate_token(original, trust=trust).token_id == original.token_id


def test_revalidation_fails_when_device_removed_during_prompt(drive, signing_key, trust):
    token_path = write_token(drive, signing_key)
    original = verify_token_file(token_path, trust=trust)
    token_path.unlink()
    with pytest.raises(AccessTokenError, match="unavailable"):
        revalidate_token(original, trust=trust)


def test_revalidation_fails_when_device_swapped_during_prompt(drive, signing_key, trust):
    original = verify_token_file(write_token(drive, signing_key), trust=trust)
    write_token(drive, signing_key, token_id="REPLACED", vault_id="VAULT-REPLACED")
    with pytest.raises(AccessTokenError, match="changed"):
        revalidate_token(original, trust=trust)


# ---------------------------------------------------------------------------
# Hostile bytes on the drive must always surface as AccessTokenError, so that
# discovery skips them and the monitor treats them as "invalid" (fails closed).
# ---------------------------------------------------------------------------


def _token_path(drive):
    return drive / token_filename_for_scope(DEFAULT_SCOPE)


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff\xfe\x00 not utf-8",
        rb'{"payload": {"token_id": "\ud800"}, "signature": "AAAA"}',
        b"[" * 50_000,
        b'{"payload": [], "signature": "AAAA"}',
        b"",
    ],
    ids=["invalid-utf8", "lone-surrogate", "deep-nesting", "payload-not-object", "empty"],
)
def test_hostile_token_bytes_raise_access_token_error(drive, trust, raw):
    _token_path(drive).write_bytes(raw)
    with pytest.raises(AccessTokenError):
        verify_token_file(_token_path(drive), trust=trust)
    assert discover_verified_tokens(trust=trust, extra_roots=[drive]) == []


def test_oversized_token_is_refused_before_parsing(drive, trust):
    _token_path(drive).write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(AccessTokenError, match="too large"):
        verify_token_file(_token_path(drive), trust=trust)


def _resign(token_path, signing_key, mutate):
    document = json.loads(token_path.read_text(encoding="utf-8"))
    mutate(document["payload"])
    document["signature"] = base64.urlsafe_b64encode(
        signing_key.sign(_canonical_payload(document["payload"]))
    ).decode("ascii")
    token_path.write_text(json.dumps(document), encoding="utf-8")


@pytest.mark.parametrize(
    "field, value",
    [("n", 2**20), ("r", 64), ("p", 16), ("length", 1024)],
    ids=["n-too-large", "r-too-large", "p-too-large", "length-too-large"],
)
def test_signed_but_unreasonable_scrypt_cost_is_refused_without_running_it(
    drive, signing_key, trust, monkeypatch, field, value
):
    """Even a correctly signed token must not be able to demand an unbounded
    amount of memory or time from the machine that checks the password."""
    token_path = write_token(drive, signing_key)
    _resign(token_path, signing_key, lambda payload: payload["password_kdf"].__setitem__(field, value))
    token = verify_token_file(token_path, trust=trust)

    def spy(**kwargs):
        raise AssertionError("scrypt must not run with parameters above the policy")

    monkeypatch.setattr("tetherlock.access.Scrypt", spy)
    with pytest.raises(AccessTokenError, match="maximum policy"):
        unlock_verified_token(token, PASSWORD)


def test_invalid_scrypt_parameters_become_access_token_error(drive, signing_key, trust):
    token_path = write_token(drive, signing_key)
    _resign(token_path, signing_key, lambda payload: payload["password_kdf"].__setitem__("n", 3 * 2**14))
    token = verify_token_file(token_path, trust=trust)
    with pytest.raises(AccessTokenError, match="invalid"):
        unlock_verified_token(token, PASSWORD)
