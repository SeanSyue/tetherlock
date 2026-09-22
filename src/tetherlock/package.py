"""Password-encrypted folder packages for handing data from one machine to another.

File layout::

    MAGIC | uint32 big-endian header length | JSON header | AES-256-GCM ciphertext

The key is derived from the password with scrypt. The JSON header (KDF
parameters, salt, nonce) is authenticated as associated data, so changing
any byte of the header or the ciphertext makes decryption fail.

Extraction refuses archives that would write outside the destination
(zip-slip), and caps the number of entries and the total unpacked size.
"""

from __future__ import annotations

import base64
import io
import json
import os
import struct
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"TLPKG1\x00"
MIN_PASSWORD_LENGTH = 12
MAX_MEMBERS = 5000
MAX_UNPACKED_BYTES = 10 * 1024 * 1024 * 1024
MANIFEST_NAME = "manifest.json"
MIN_SCRYPT_N = 2**14
# The header is read before the password can be checked, so everything in it
# is attacker-controlled. These bounds cap the work one extraction can be made
# to do: at most 128 * N * r = 64 MiB of memory for key derivation.
MAX_SCRYPT_N = 2**16
MAX_SCRYPT_R = 8
MAX_SCRYPT_P = 4
MAX_HEADER_BYTES = 4096
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
SALT_BYTES = 16
NONCE_BYTES = 12


class PackageError(ValueError):
    pass


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PackageError(f"Package password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if n < MIN_SCRYPT_N or r < 1 or p < 1:
        raise PackageError("Package key-derivation parameters are below the minimum policy.")
    if n > MAX_SCRYPT_N or r > MAX_SCRYPT_R or p > MAX_SCRYPT_P or n & (n - 1):
        raise PackageError("Package key-derivation parameters are outside the allowed range.")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def create_package(source_dir: Path, output_path: Path, password: str, manifest: dict) -> Path:
    source_dir = source_dir.resolve()
    if not source_dir.is_dir():
        raise PackageError("Source must be a directory.")
    files: list[Path] = []
    for candidate in source_dir.rglob("*"):
        if candidate.is_symlink():
            raise PackageError(f"Symbolic links are not allowed in a package: {candidate}")
        if not candidate.is_file():
            continue
        if source_dir not in candidate.resolve().parents:
            raise PackageError(f"File lies outside the source directory: {candidate}")
        if candidate.relative_to(source_dir).as_posix() == MANIFEST_NAME:
            raise PackageError(f"The source directory must not contain its own {MANIFEST_NAME}.")
        files.append(candidate)

    internal_manifest = dict(manifest)
    internal_manifest["format_version"] = 1
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(internal_manifest, ensure_ascii=False, indent=2))
        for path in files:
            archive.write(path, path.relative_to(source_dir).as_posix())

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    n, r, p = 2**15, 8, 1
    header = {
        "format": 1,
        "kdf": "scrypt",
        "n": n,
        "r": r,
        "p": p,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = _derive_key(password, salt, n, r, p)
    ciphertext = AESGCM(key).encrypt(nonce, buffer.getvalue(), header_bytes)
    if len(MAGIC) + 4 + len(header_bytes) + len(ciphertext) > MAX_PACKAGE_BYTES:
        # extract_package() would refuse it, so do not produce it.
        raise PackageError("Package would be larger than the safety limit allows.")

    # Write to a temporary file first and swap it in, so an interrupted write
    # never leaves a truncated package under the final name.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_bytes(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext)
    temporary.replace(output_path)
    return output_path


def extract_package(package_path: Path, destination_dir: Path, password: str) -> dict:
    # The stat check rejects obviously oversized files early. The bounded
    # read also covers growth/replacement between stat and open; the extra
    # byte distinguishes an exact-limit file from one that must be refused.
    try:
        size = package_path.stat().st_size
    except OSError as exc:
        raise PackageError("Package cannot be read.") from exc
    if size > MAX_PACKAGE_BYTES:
        raise PackageError("Package is larger than the safety limit allows.")
    try:
        with package_path.open("rb") as handle:
            raw = handle.read(MAX_PACKAGE_BYTES + 1)
    except OSError as exc:
        raise PackageError("Package cannot be read.") from exc
    if len(raw) > MAX_PACKAGE_BYTES:
        raise PackageError("Package is larger than the safety limit allows.")
    if not raw.startswith(MAGIC):
        raise PackageError("Not a valid package file.")
    offset = len(MAGIC)
    if len(raw) < offset + 4:
        raise PackageError("Package header is damaged.")
    header_len = struct.unpack(">I", raw[offset : offset + 4])[0]
    offset += 4
    if header_len > MAX_HEADER_BYTES or len(raw) < offset + header_len:
        raise PackageError("Package header is damaged.")
    header_bytes = raw[offset : offset + header_len]
    ciphertext = raw[offset + header_len :]
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        if header.get("format") != 1 or header.get("kdf") != "scrypt":
            raise ValueError("unsupported format")
        salt = base64.b64decode(header["salt"], validate=True)
        nonce = base64.b64decode(header["nonce"], validate=True)
        n, r, p = int(header["n"]), int(header["r"]), int(header["p"])
    except Exception as exc:
        raise PackageError("Package header is damaged.") from exc
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise PackageError("Package header is damaged.")

    key = _derive_key(password, salt, n, r, p)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header_bytes)
    except Exception as exc:
        raise PackageError("Wrong password, or the package has been modified.") from exc

    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(plaintext), "r") as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise PackageError("Package contains more files than the safety limit allows.")
        if sum(member.file_size for member in members) > MAX_UNPACKED_BYTES:
            raise PackageError("Package would unpack to more than the 10 GB safety limit.")
        destination_resolved = destination_dir.resolve()
        for member in members:
            target = (destination_dir / member.filename).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise PackageError("Package contains an unsafe path.")
        archive.extractall(destination_dir)
    return json.loads((destination_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
