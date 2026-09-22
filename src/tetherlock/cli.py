"""Offline administration: generate signing keys, manage the trust manifest,
issue tokens to a drive, and check a drive's token.

Run on the administrator's machine. Only the public key (or the trust
manifest) is ever copied to the machines that verify tokens.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tetherlock.access import (
    DEFAULT_SCOPE,
    SINGLE_PUBLIC_KEY_FILENAME,
    TRUSTED_KEYS_MANIFEST_FILENAME,
    TrustStore,
    _parse_iso_datetime,
    get_volume_serial,
    issue_token_document,
    load_private_key,
    token_filename_for_scope,
    unlock_verified_token,
    verify_token_file,
)

MIN_WORKSPACE_PASSWORD_LENGTH = 10


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ask_new_password(label: str) -> str:
    first = getpass.getpass(f"{label}: ")
    second = getpass.getpass(f"Confirm {label.lower()}: ")
    if first != second:
        raise ValueError("Passwords do not match.")
    return first


def init_keys(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    private_path = output_dir / "access_private_key.pem"
    public_path = output_dir / SINGLE_PUBLIC_KEY_FILENAME
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Key files already exist in the output directory.")

    # The private key file is always encrypted. An unprotected signing key
    # on disk would let anyone who copies it issue valid tokens.
    password = _ask_new_password("Private-key password")
    if not password:
        raise ValueError("A private-key password is required.")

    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")
    print("Keep the private key offline. Install only the public key where tokens are verified.")
    return 0


def _manifest_path(args: argparse.Namespace) -> Path:
    return Path(args.trust_dir).expanduser().resolve() / TRUSTED_KEYS_MANIFEST_FILENAME


def _load_manifest_document(path: Path) -> dict:
    if not path.is_file():
        return {"keys": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_manifest_document(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def add_trusted_key(args: argparse.Namespace) -> int:
    """Add a public key to the manifest with no deprecation time. During a
    rotation the old and new keys are both trusted until the old one is
    deprecated."""
    public_key_pem = Path(args.public_key).expanduser().resolve().read_text(encoding="utf-8")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("The provided key is not an Ed25519 public key.")

    path = _manifest_path(args)
    manifest = _load_manifest_document(path)
    keys = manifest.setdefault("keys", [])
    if any(entry.get("key_id") == args.key_id for entry in keys):
        raise ValueError(f"key_id already exists in the trust manifest: {args.key_id}")
    keys.append({"key_id": args.key_id, "public_key_pem": public_key_pem, "deprecated_at": None})
    _write_manifest_document(path, manifest)
    print(f"Added trusted key '{args.key_id}' to {path}")
    print(f"Keys now in the manifest: {', '.join(entry['key_id'] for entry in keys)}")
    return 0


def deprecate_trusted_key(args: argparse.Namespace) -> int:
    """Stop trusting a key after a given time. This is a scheduled phase-out,
    not an instant revocation: the grace period lets machines pick up the new
    key first. After the time passes, every token that key signed fails."""
    _parse_iso_datetime(args.deprecated_at, "deprecated_at")
    path = _manifest_path(args)
    manifest = _load_manifest_document(path)
    for entry in manifest.get("keys", []):
        if entry.get("key_id") == args.key_id:
            entry["deprecated_at"] = args.deprecated_at
            _write_manifest_document(path, manifest)
            print(f"Key '{args.key_id}' will stop being trusted at {args.deprecated_at}")
            return 0
    raise ValueError(f"No such key_id in the trust manifest: {args.key_id}")


def list_trusted_keys(args: argparse.Namespace) -> int:
    path = _manifest_path(args)
    keys = _load_manifest_document(path).get("keys", [])
    if not keys:
        print(f"No trust manifest entries at {path}.")
        return 0
    for entry in keys:
        deprecated = entry.get("deprecated_at")
        status = f"deprecated at {deprecated}" if deprecated else "active, no deprecation set"
        print(f"{entry.get('key_id')}: {status}")
    return 0


def issue_token(args: argparse.Namespace) -> int:
    drive_root = Path(args.drive_root).expanduser().resolve()
    if not drive_root.is_dir():
        raise FileNotFoundError(f"Drive root does not exist: {drive_root}")

    token_path = drive_root / token_filename_for_scope(args.scope)
    if token_path.exists():
        raise FileExistsError(
            f"A token for scope '{args.scope}' already exists at {token_path}. "
            "Remove it first if you really mean to replace it."
        )

    pem_password = getpass.getpass("Private-key password: ")
    private_key = load_private_key(
        Path(args.private_key).expanduser().resolve(),
        password=pem_password.encode("utf-8") if pem_password else None,
    )

    access_password = _ask_new_password("Workspace unlock password")
    if len(access_password) < MIN_WORKSPACE_PASSWORD_LENGTH:
        raise ValueError(f"Use at least {MIN_WORKSPACE_PASSWORD_LENGTH} characters for the workspace password.")

    drive_serial = "ANY" if args.allow_copy else get_volume_serial(drive_root)
    if not drive_serial:
        raise RuntimeError("Unable to read the storage-device serial number.")

    extra_payload = None
    if args.allowed_capabilities:
        capabilities = [item.strip() for item in args.allowed_capabilities.split(",") if item.strip()]
        extra_payload = {"allowed_capabilities": capabilities}

    document = issue_token_document(
        private_key=private_key,
        token_id=args.token_id or secrets.token_hex(16),
        scope=args.scope,
        vault_id=args.vault_id or secrets.token_hex(12),
        password=access_password,
        drive_serial=drive_serial,
        issued_at=_utc_now_text(),
        expires_at=args.expires_at,
        extra_payload=extra_payload,
    )
    token_path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    if os.name == "nt":
        try:
            subprocess.run(["attrib", "+h", str(token_path)], check=False, capture_output=True)
        except OSError:
            pass
    print(f"Issued token: {token_path}")
    print(f"Drive serial binding: {drive_serial}")
    if extra_payload:
        print(f"Allowed capabilities: {', '.join(extra_payload['allowed_capabilities'])}")
    print("Other scopes can be issued to the same drive independently; each gets its own file and password.")
    return 0


def verify_token(args: argparse.Namespace) -> int:
    trust = TrustStore.from_directory(Path(args.trust_dir).expanduser().resolve())
    token_path = Path(args.drive_root).expanduser().resolve() / token_filename_for_scope(args.scope)
    token = verify_token_file(token_path, trust=trust, expected_scope=args.scope)
    print(f"Signature valid. token_id={token.token_id} scope={token.scope} binding={token.drive_serial}")
    if args.check_password:
        grant = unlock_verified_token(token, getpass.getpass("Workspace unlock password: "))
        print(f"Password accepted. Vault location: {grant.vault_root}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tetherlock", description="Tetherlock access-token administration")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-keys", help="Generate an Ed25519 signing key pair")
    init.add_argument("--output-dir", required=True)
    init.set_defaults(func=init_keys)

    add_key = sub.add_parser("add-trusted-key", help="Add a public key to a trust manifest")
    add_key.add_argument("--trust-dir", required=True)
    add_key.add_argument("--key-id", required=True)
    add_key.add_argument("--public-key", required=True)
    add_key.set_defaults(func=add_trusted_key)

    deprecate_key = sub.add_parser("deprecate-trusted-key", help="Stop trusting a manifest key after a given time")
    deprecate_key.add_argument("--trust-dir", required=True)
    deprecate_key.add_argument("--key-id", required=True)
    deprecate_key.add_argument("--deprecated-at", required=True, help="ISO-8601 timestamp")
    deprecate_key.set_defaults(func=deprecate_trusted_key)

    list_keys = sub.add_parser("list-trusted-keys", help="List the entries in a trust manifest")
    list_keys.add_argument("--trust-dir", required=True)
    list_keys.set_defaults(func=list_trusted_keys)

    issue = sub.add_parser("issue-token", help="Write a signed access token to a drive")
    issue.add_argument("--private-key", required=True)
    issue.add_argument("--drive-root", required=True)
    issue.add_argument("--scope", default=DEFAULT_SCOPE)
    issue.add_argument("--token-id", default="")
    issue.add_argument("--vault-id", default="")
    issue.add_argument("--expires-at", default="", help="ISO-8601 timestamp, optional")
    issue.add_argument(
        "--allow-copy",
        action="store_true",
        help="Development only: do not bind the token to this volume's serial number",
    )
    issue.add_argument(
        "--allowed-capabilities",
        default="",
        help="Comma-separated capabilities for maintenance tokens (scope maintenance.v1)",
    )
    issue.set_defaults(func=issue_token)

    verify = sub.add_parser("verify-token", help="Check the token on a drive against a trust directory")
    verify.add_argument("--trust-dir", required=True)
    verify.add_argument("--drive-root", required=True)
    verify.add_argument("--scope", default=DEFAULT_SCOPE)
    verify.add_argument("--check-password", action="store_true", help="Also prompt for and check the password")
    verify.set_defaults(func=verify_token)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
