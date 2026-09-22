from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tetherlock.access import (
    DEFAULT_SCOPE,
    TrustStore,
    get_volume_serial,
    issue_token_document,
    token_filename_for_scope,
)

PASSWORD = "correct horse battery staple"


def public_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_token(
    drive: Path,
    private_key: Ed25519PrivateKey,
    *,
    token_id: str = "TOKEN-001",
    scope: str = DEFAULT_SCOPE,
    vault_id: str = "VAULT-001",
    password: str = PASSWORD,
    drive_serial: str | None = None,
    **kwargs,
) -> Path:
    document = issue_token_document(
        private_key=private_key,
        token_id=token_id,
        scope=scope,
        vault_id=vault_id,
        password=password,
        drive_serial=get_volume_serial(drive) if drive_serial is None else drive_serial,
        issued_at="2026-01-01T00:00:00+00:00",
        **kwargs,
    )
    token_path = drive / token_filename_for_scope(scope)
    token_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return token_path


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def public_key_path(tmp_path: Path, signing_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "access_public_key.pem"
    path.write_bytes(public_pem(signing_key))
    return path


@pytest.fixture
def trust(public_key_path: Path) -> TrustStore:
    return TrustStore.from_public_key(public_key_path)


@pytest.fixture
def drive(tmp_path: Path) -> Path:
    path = tmp_path / "drive"
    path.mkdir()
    return path
