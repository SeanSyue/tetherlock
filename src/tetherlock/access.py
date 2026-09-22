"""Signed access tokens stored on a removable authorization device.

A token is a small JSON document written to the root of a drive. It carries
a payload (scope, vault id, device binding, expiry, password verifier) and an
Ed25519 signature over the canonical form of that payload. The machine that
verifies tokens only ever holds public keys; the signing key stays offline.

Trust is always explicit: every verification call takes a ``TrustStore``
built by the host application from a location it controls. Nothing in this
module reads environment variables or searches default paths to decide which
public keys are trusted, so an unprivileged user cannot swap in their own key.
"""

from __future__ import annotations

import base64
import ctypes
import hmac
import json
import os
import re
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

TOKEN_SCHEMA_VERSION = 1
DEFAULT_SCOPE = "workspace.secure.v1"
DEFAULT_VAULT_DIRNAME = ".tetherlock_vault"
TOKEN_FILENAME_PREFIX = ".tetherlock_access"

TRUSTED_KEYS_MANIFEST_FILENAME = "trusted_keys.json"
SINGLE_PUBLIC_KEY_FILENAME = "access_public_key.pem"

# Password verifier parameters used when issuing, and the floor enforced when
# verifying. A token that asks for a weaker scrypt cost is rejected outright.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
SCRYPT_MIN_N = 2**14
# Upper bounds keep one verification to a bounded amount of memory and time
# (128 * N * r bytes = 64 MiB at the maximum), whoever signed the token.
SCRYPT_MAX_N = 2**16
SCRYPT_MAX_R = 8
SCRYPT_MAX_P = 4

# Token files and trust manifests are small. Anything larger is refused before
# it is parsed, so a hostile drive cannot make verification read or parse an
# arbitrarily large file.
MAX_TOKEN_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024

# vault_id is joined onto the drive root to build a path. The allow-list
# excludes ".", "..", path separators, drive letters and absolute paths:
# pathlib's "/" operator discards everything on its left when the right-hand
# side is absolute, so an unchecked vault_id could redirect the vault anywhere.
_VAULT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# scope becomes part of a filename, so it is validated the same way even
# though callers normally pass fixed literals.
_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class AccessTokenError(ValueError):
    """Raised when an authorization token is malformed, invalid, or expired."""


def token_filename_for_scope(scope: str) -> str:
    """Each scope gets its own token file, so one drive can carry several
    independent authorizations. Each has its own signature and its own
    password: sharing a drive does not mean sharing a secret, and leaking one
    scope's password does not open another scope.
    """
    if not scope or not _SCOPE_PATTERN.fullmatch(scope):
        raise AccessTokenError(f"Invalid scope for token filename: {scope!r}")
    return f"{TOKEN_FILENAME_PREFIX}.{scope}.json"


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKeyEntry:
    key_id: str
    public_key: Ed25519PublicKey
    deprecated_at: datetime | None = None

    def is_active(self, now: datetime) -> bool:
        return self.deprecated_at is None or now < self.deprecated_at


@dataclass(frozen=True)
class TrustStore:
    """The set of public keys a host accepts token signatures from.

    Several keys can be trusted at once, each with an optional deprecation
    time. During key rotation the old and new keys overlap for a grace period,
    so machines do not all have to switch at the same moment. Once a key's
    ``deprecated_at`` passes, every token it signed stops verifying.
    """

    entries: tuple[TrustedKeyEntry, ...] = field(default_factory=tuple)

    def active_keys(self, now: datetime | None = None) -> list[TrustedKeyEntry]:
        now = now or datetime.now(timezone.utc)
        return [entry for entry in self.entries if entry.is_active(now)]

    def verifies(self, signature: bytes, message: bytes, *, now: datetime | None = None) -> bool:
        return any(_signature_matches(entry.public_key, signature, message) for entry in self.active_keys(now))

    @classmethod
    def from_public_key(cls, path: Path, *, key_id: str = "default") -> "TrustStore":
        return cls(entries=(TrustedKeyEntry(key_id=key_id, public_key=load_public_key(path)),))

    @classmethod
    def from_manifest(cls, path: Path) -> "TrustStore":
        return cls(entries=tuple(_load_trusted_keys_manifest(path)))

    @classmethod
    def from_directory(cls, directory: Path) -> "TrustStore":
        """Load from a directory the host controls (for example one that only
        administrators can write to). A ``trusted_keys.json`` manifest takes
        precedence; otherwise a single ``access_public_key.pem`` is trusted
        with no deprecation. An empty store is returned when neither exists.
        """
        manifest = directory / TRUSTED_KEYS_MANIFEST_FILENAME
        if manifest.is_file():
            return cls.from_manifest(manifest)
        single = directory / SINGLE_PUBLIC_KEY_FILENAME
        if single.is_file():
            return cls.from_public_key(single)
        return cls()


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise AccessTokenError("Unable to load the trusted access public key.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AccessTokenError("The trusted access key is not an Ed25519 public key.")
    return key


def load_private_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (OSError, ValueError, TypeError) as exc:
        raise AccessTokenError("Unable to load the access signing private key.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AccessTokenError("The access signing key is not an Ed25519 private key.")
    return key


def _read_json_file(path: Path, max_bytes: int, label: str):
    """Read and parse a small JSON file from an untrusted location.

    Every way the bytes can be wrong (too large, not UTF-8, not JSON, nested
    deeply enough to exhaust the parser) becomes AccessTokenError, so callers
    that treat AccessTokenError as "invalid" never see a different exception
    escape and skip their failure handling.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise AccessTokenError(f"Unable to read {label}.") from exc
    if len(raw) > max_bytes:
        raise AccessTokenError(f"{label.capitalize()} is too large.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AccessTokenError(f"{label.capitalize()} is malformed.") from exc


def _load_trusted_keys_manifest(manifest_path: Path) -> list[TrustedKeyEntry]:
    manifest = _read_json_file(manifest_path, MAX_MANIFEST_BYTES, "the trusted keys manifest")

    raw_entries = manifest.get("keys") if isinstance(manifest, dict) else None
    # An empty or missing key list is an error, not "trust nothing quietly":
    # a broken manifest should be noticed, not silently lock everyone out.
    if not isinstance(raw_entries, list) or not raw_entries:
        raise AccessTokenError("Trusted keys manifest has no keys.")

    entries: list[TrustedKeyEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise AccessTokenError("Trusted keys manifest entry is malformed.")
        key_id = str(raw.get("key_id", "")).strip()
        pem_text = raw.get("public_key_pem")
        if not key_id or not isinstance(pem_text, str) or not pem_text.strip():
            raise AccessTokenError("Trusted keys manifest entry is missing key_id/public_key_pem.")
        deprecated_raw = raw.get("deprecated_at")
        deprecated_at = (
            _parse_iso_datetime(deprecated_raw, f"deprecated_at for key_id={key_id!r}")
            if deprecated_raw
            else None
        )
        try:
            key = serialization.load_pem_public_key(pem_text.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise AccessTokenError(f"Invalid public key for key_id={key_id!r}.") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise AccessTokenError(f"key_id={key_id!r} is not an Ed25519 public key.")
        entries.append(TrustedKeyEntry(key_id=key_id, public_key=key, deprecated_at=deprecated_at))
    return entries


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedAccessToken:
    token_path: Path
    drive_root: Path
    token_id: str
    scope: str
    vault_id: str
    vault_dirname: str
    expires_at: str
    drive_serial: str
    payload: dict

    @property
    def vault_root(self) -> Path:
        return self.drive_root / self.vault_dirname / self.vault_id


@dataclass(frozen=True)
class AccessGrant:
    """Proof that a verified token was also unlocked with its password."""

    token: VerifiedAccessToken

    @property
    def token_path(self) -> Path:
        return self.token.token_path

    @property
    def drive_root(self) -> Path:
        return self.token.drive_root

    @property
    def vault_root(self) -> Path:
        return self.token.vault_root

    @property
    def scope(self) -> str:
        return self.token.scope

    @property
    def token_id(self) -> str:
        return self.token.token_id


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise AccessTokenError(f"Invalid base64 value for {label}.") from exc


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_iso_datetime(value: str, label: str) -> datetime:
    if not value:
        raise AccessTokenError(f"Missing {label}.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AccessTokenError(f"Invalid {label}.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _signature_matches(public_key: Ed25519PublicKey, signature: bytes, payload_bytes: bytes) -> bool:
    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return False
    return True


def get_volume_serial(root: Path) -> str:
    """Return a stable-enough volume identifier when available.

    Windows uses the volume serial number. Other platforms use st_dev as a
    best-effort development fallback.
    """
    resolved = root.resolve()
    if os.name == "nt":
        volume_path = str(resolved)
        if len(volume_path) >= 2 and volume_path[1] == ":":
            volume_path = volume_path[:3]
        serial = ctypes.c_uint32()
        max_component = ctypes.c_uint32()
        flags = ctypes.c_uint32()
        volume_name = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(volume_path),
            volume_name,
            len(volume_name),
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            fs_name,
            len(fs_name),
        )
        if not ok:
            return ""
        return f"{serial.value:08X}"

    try:
        return f"DEV-{resolved.stat().st_dev:X}"
    except OSError:
        return ""


def iter_candidate_drive_roots(extra_roots: Iterable[Path] = ()) -> Iterable[Path]:
    """Yield directories that might hold a token: the explicit ``extra_roots``
    first, then every mounted drive letter (Windows) or removable-media mount
    point (Linux)."""
    seen: set[str] = set()

    def emit(path: Path):
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen or not path.exists() or not path.is_dir():
            return None
        seen.add(key)
        return path

    for root in extra_roots:
        candidate = emit(root)
        if candidate is not None:
            yield candidate

    if os.name == "nt":
        for letter in string.ascii_uppercase:
            candidate = emit(Path(f"{letter}:\\"))
            if candidate is not None:
                yield candidate
        return

    user = os.environ.get("USER", "")
    patterns = [Path("/mnt"), Path("/media") / user, Path("/run/media") / user]
    for base in patterns:
        if not base.is_dir():
            continue
        for path in base.iterdir():
            candidate = emit(path)
            if candidate is not None:
                yield candidate


def _validate_payload(payload: dict, token_path: Path, expected_scope: str | None) -> VerifiedAccessToken:
    if payload.get("schema_version") != TOKEN_SCHEMA_VERSION:
        raise AccessTokenError("Unsupported access token schema version.")

    token_id = str(payload.get("token_id", "")).strip()
    scope = str(payload.get("scope", "")).strip()
    vault_id = str(payload.get("vault_id", "")).strip()
    vault_dirname = str(payload.get("vault_dirname", DEFAULT_VAULT_DIRNAME)).strip()
    expires_at = str(payload.get("expires_at", "")).strip()
    expected_serial = str(payload.get("drive_serial", "")).strip().upper()

    if not token_id or not scope or not vault_id:
        raise AccessTokenError("Access token is missing required fields.")
    if expected_scope and scope != expected_scope:
        raise AccessTokenError("Access token scope does not match the requested module.")
    # An explicit empty string survives .get(key, default) and would make
    # pathlib silently drop that path segment, so it is rejected here rather
    # than relying on nobody ever signing such a token.
    if not vault_dirname:
        raise AccessTokenError("Invalid vault directory name.")
    if Path(vault_dirname).name != vault_dirname or vault_dirname in {".", ".."}:
        raise AccessTokenError("Invalid vault directory name.")
    if not _VAULT_ID_PATTERN.fullmatch(vault_id):
        raise AccessTokenError("Invalid vault identifier.")

    if expires_at:
        if _parse_iso_datetime(expires_at, "expires_at") <= datetime.now(timezone.utc):
            raise AccessTokenError("Access token has expired.")

    drive_root = token_path.parent
    actual_serial = get_volume_serial(drive_root).upper()
    if expected_serial and expected_serial not in {"ANY", actual_serial}:
        raise AccessTokenError("Access token is bound to a different storage device.")

    return VerifiedAccessToken(
        token_path=token_path,
        drive_root=drive_root,
        token_id=token_id,
        scope=scope,
        vault_id=vault_id,
        vault_dirname=vault_dirname,
        expires_at=expires_at,
        drive_serial=expected_serial,
        payload=payload,
    )


def verify_token_file(
    token_path: Path,
    *,
    trust: TrustStore,
    expected_scope: str | None = DEFAULT_SCOPE,
) -> VerifiedAccessToken:
    document = _read_json_file(token_path, MAX_TOKEN_BYTES, "the access token")

    payload = document.get("payload") if isinstance(document, dict) else None
    signature_text = document.get("signature") if isinstance(document, dict) else None
    if not isinstance(payload, dict) or not isinstance(signature_text, str):
        raise AccessTokenError("Access token document is malformed.")

    if not trust.active_keys():
        raise AccessTokenError("No trusted access public key is installed.")
    signature_bytes = _b64decode(signature_text, "signature")
    try:
        # JSON can carry lone surrogates ("\ud800") that cannot be encoded
        # back to UTF-8, so canonicalisation itself can fail on hostile input.
        payload_bytes = _canonical_payload(payload)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AccessTokenError("Access token document is malformed.") from exc
    if not trust.verifies(signature_bytes, payload_bytes):
        raise AccessTokenError("Access token signature is invalid.")

    return _validate_payload(payload, token_path, expected_scope)


def discover_verified_tokens(
    *,
    trust: TrustStore,
    expected_scope: str = DEFAULT_SCOPE,
    extra_roots: Iterable[Path] = (),
) -> list[VerifiedAccessToken]:
    tokens: list[VerifiedAccessToken] = []
    filename = token_filename_for_scope(expected_scope)
    for root in iter_candidate_drive_roots(extra_roots):
        token_path = root / filename
        if not token_path.is_file():
            continue
        try:
            tokens.append(verify_token_file(token_path, trust=trust, expected_scope=expected_scope))
        except AccessTokenError:
            # Discovery is intentionally silent. An invalid file must not
            # reveal that a protected module exists or interrupt normal use.
            continue
    return tokens


def _derive_password_verifier(password: str, payload: dict) -> bytes:
    kdf_info = payload.get("password_kdf")
    if not isinstance(kdf_info, dict) or kdf_info.get("name") != "scrypt":
        raise AccessTokenError("Unsupported password verifier configuration.")
    salt = _b64decode(str(kdf_info.get("salt", "")), "password salt")
    try:
        n = int(kdf_info.get("n", SCRYPT_N))
        r = int(kdf_info.get("r", SCRYPT_R))
        p = int(kdf_info.get("p", SCRYPT_P))
        length = int(kdf_info.get("length", SCRYPT_LENGTH))
    except (TypeError, ValueError) as exc:
        raise AccessTokenError("Invalid password verifier parameters.") from exc
    if n < SCRYPT_MIN_N or r < 1 or p < 1 or length < 16:
        raise AccessTokenError("Password verifier parameters are below the minimum policy.")
    if n > SCRYPT_MAX_N or r > SCRYPT_MAX_R or p > SCRYPT_MAX_P or length > 64:
        raise AccessTokenError("Password verifier parameters are above the maximum policy.")
    try:
        kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
        return kdf.derive(password.encode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        # e.g. n not a power of two, or a password with lone surrogates
        raise AccessTokenError("Password verifier configuration is invalid.") from exc


def unlock_verified_token(token: VerifiedAccessToken, password: str) -> AccessGrant:
    """Check the password against the verifier in the signed payload. The
    token never stores the password itself, and the comparison is constant
    time."""
    if not password:
        raise AccessTokenError("Password is required.")
    expected = _b64decode(str(token.payload.get("password_verifier", "")), "password verifier")
    actual = _derive_password_verifier(password, token.payload)
    if not hmac.compare_digest(actual, expected):
        raise AccessTokenError("Password verification failed.")
    return AccessGrant(token=token)


def revalidate_token(previous: VerifiedAccessToken, *, trust: TrustStore) -> VerifiedAccessToken:
    """Re-read and re-verify a token right before unlocking with it.

    Typing a password takes seconds. In that window the drive can be pulled
    out, or replaced by a different device mounted at the same drive letter.
    Unlocking with the token object cached before the prompt would then point
    the vault at whatever device now sits at that path. Call this after the
    user confirms the password and before ``unlock_verified_token()``.
    """
    try:
        current = verify_token_file(previous.token_path, trust=trust, expected_scope=previous.scope)
    except AccessTokenError as exc:
        raise AccessTokenError("Authorization device changed or became unavailable during verification.") from exc

    if (
        current.token_id != previous.token_id
        or current.vault_id != previous.vault_id
        or current.vault_dirname != previous.vault_dirname
        or current.drive_serial != previous.drive_serial
    ):
        raise AccessTokenError("Authorization device changed during verification.")

    return current


def issue_token_document(
    *,
    private_key: Ed25519PrivateKey,
    token_id: str,
    scope: str,
    vault_id: str,
    password: str,
    drive_serial: str = "",
    issued_at: str,
    expires_at: str = "",
    vault_dirname: str = DEFAULT_VAULT_DIRNAME,
    extra_payload: dict | None = None,
) -> dict:
    """Build and sign a token document.

    ``extra_payload`` lets callers add fields (such as a capability list)
    before signing, without this function knowing what those fields mean.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = os.urandom(16)
    kdf_info = {
        "name": "scrypt",
        "salt": _b64encode(salt),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "length": SCRYPT_LENGTH,
    }
    verifier = Scrypt(salt=salt, length=SCRYPT_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )
    payload = {
        "schema_version": TOKEN_SCHEMA_VERSION,
        "token_id": token_id,
        "scope": scope,
        "vault_id": vault_id,
        "vault_dirname": vault_dirname,
        "drive_serial": drive_serial.upper(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "password_kdf": kdf_info,
        "password_verifier": _b64encode(verifier),
    }
    if extra_payload:
        payload.update(extra_payload)
    signature = private_key.sign(_canonical_payload(payload))
    return {"payload": payload, "signature": _b64encode(signature)}
