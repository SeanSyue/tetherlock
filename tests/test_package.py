from __future__ import annotations

import io
from pathlib import Path
import json
import os
import zipfile

import pytest

from tetherlock import package as pkg
from tetherlock.package import PackageError, create_package, extract_package

PASSWORD = "correct horse battery staple"


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "source"
    (directory / "nested").mkdir(parents=True)
    (directory / "data.txt").write_text("sensitive", encoding="utf-8")
    (directory / "nested" / "more.txt").write_text("more", encoding="utf-8")
    return directory


def test_round_trip(tmp_path, source):
    package_path = create_package(source, tmp_path / "out.pkg", PASSWORD, {"kind": "example"})
    raw = package_path.read_bytes()
    assert raw.startswith(pkg.MAGIC)
    assert b"sensitive" not in raw
    manifest = extract_package(package_path, tmp_path / "target", PASSWORD)
    assert manifest == {"kind": "example", "format_version": 1}
    assert (tmp_path / "target" / "nested" / "more.txt").read_text(encoding="utf-8") == "more"
    assert not (tmp_path / "out.pkg.tmp").exists()


def test_wrong_password_is_rejected(tmp_path, source):
    package_path = create_package(source, tmp_path / "out.pkg", PASSWORD, {})
    with pytest.raises(PackageError, match="Wrong password"):
        extract_package(package_path, tmp_path / "target", "wrong password long enough")


def test_short_password_is_rejected(tmp_path, source):
    with pytest.raises(PackageError, match="at least"):
        create_package(source, tmp_path / "out.pkg", "short", {})


@pytest.mark.parametrize("where", ["header", "ciphertext"])
def test_any_modification_is_detected(tmp_path, source, where):
    package_path = create_package(source, tmp_path / "out.pkg", PASSWORD, {})
    raw = bytearray(package_path.read_bytes())
    header_len = int.from_bytes(raw[len(pkg.MAGIC) : len(pkg.MAGIC) + 4], "big")
    header_start = len(pkg.MAGIC) + 4
    if where == "header":
        # Flip a byte inside the base64 nonce value, keeping the JSON parseable.
        header = raw[header_start : header_start + header_len].decode("utf-8")
        index = header_start + header.index('"nonce":"') + len('"nonce":"')
        raw[index] = ord("B") if raw[index] != ord("B") else ord("C")
    else:
        raw[-1] ^= 0x01
    package_path.write_bytes(bytes(raw))
    with pytest.raises(PackageError):
        extract_package(package_path, tmp_path / "target", PASSWORD)


def test_not_a_package(tmp_path):
    bogus = tmp_path / "bogus.pkg"
    bogus.write_bytes(b"PK\x03\x04 not ours")
    with pytest.raises(PackageError, match="Not a valid"):
        extract_package(bogus, tmp_path / "target", PASSWORD)


def test_source_with_own_manifest_is_rejected(tmp_path, source):
    (source / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PackageError, match="manifest"):
        create_package(source, tmp_path / "out.pkg", PASSWORD, {})


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_symlinks_are_rejected(tmp_path, source):
    try:
        (source / "link.txt").symlink_to(source / "data.txt")
    except OSError:
        pytest.skip("creating symlinks needs extra privileges on this system")
    with pytest.raises(PackageError, match="Symbolic"):
        create_package(source, tmp_path / "out.pkg", PASSWORD, {})


def _encrypt_zip(tmp_path, entries: dict[str, bytes]):
    """Build a correctly encrypted package around an arbitrary zip, to test
    the extraction-side checks that a normal create_package never triggers."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    salt, nonce = os.urandom(16), os.urandom(12)
    import base64

    header = json.dumps(
        {"format": 1, "kdf": "scrypt", "n": 2**14, "r": 8, "p": 1,
         "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode()},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    key = pkg._derive_key(PASSWORD, salt, 2**14, 8, 1)
    body = AESGCM(key).encrypt(nonce, buffer.getvalue(), header)
    path = tmp_path / "crafted.pkg"
    path.write_bytes(pkg.MAGIC + len(header).to_bytes(4, "big") + header + body)
    return path


def test_zip_slip_is_blocked(tmp_path):
    crafted = _encrypt_zip(tmp_path, {"manifest.json": b"{}", "../escaped.txt": b"x"})
    with pytest.raises(PackageError, match="unsafe path"):
        extract_package(crafted, tmp_path / "target", PASSWORD)
    assert not (tmp_path / "escaped.txt").exists()


def test_member_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(pkg, "MAX_MEMBERS", 3)
    crafted = _encrypt_zip(tmp_path, {f"f{i}.txt": b"x" for i in range(4)})
    with pytest.raises(PackageError, match="more files"):
        extract_package(crafted, tmp_path / "target", PASSWORD)


def test_weak_kdf_in_header_is_refused(tmp_path):
    header = json.dumps({"format": 1, "kdf": "scrypt", "n": 1024, "r": 8, "p": 1,
                         "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA"}).encode()
    crafted = tmp_path / "weak.pkg"
    crafted.write_bytes(pkg.MAGIC + len(header).to_bytes(4, "big") + header + b"\x00" * 32)
    with pytest.raises(PackageError, match="minimum policy"):
        extract_package(crafted, tmp_path / "target", PASSWORD)


# ---------------------------------------------------------------------------
# The header is attacker-controlled and read before the password is checked:
# refuse unreasonable values before any key derivation runs.
# ---------------------------------------------------------------------------

GOOD_HEADER = {
    "format": 1, "kdf": "scrypt", "n": 2**15, "r": 8, "p": 1,
    "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA",
}


def _raw_package(tmp_path, header, *, header_len=None):
    header_bytes = json.dumps(header).encode()
    length = len(header_bytes) if header_len is None else header_len
    path = tmp_path / "hostile.pkg"
    path.write_bytes(pkg.MAGIC + length.to_bytes(4, "big") + header_bytes + b"\x00" * 32)
    return path


@pytest.mark.parametrize(
    "change",
    [
        {"n": 2**30}, {"r": 1024}, {"p": 1024}, {"n": 3 * 2**14}, {"format": 2}, {"kdf": "pbkdf2"},
        {"salt": "AAAA"}, {"nonce": "AAAA"}, {"salt": "not base64!!"},
    ],
    ids=[
        "huge-n", "huge-r", "huge-p", "n-not-power-of-two", "unknown-format", "unknown-kdf",
        "short-salt", "short-nonce", "bad-base64",
    ],
)
def test_hostile_header_is_refused_before_key_derivation(tmp_path, monkeypatch, change):
    calls = []

    def spy(**kwargs):
        calls.append(kwargs)
        raise AssertionError("scrypt must not run on a rejected header")

    monkeypatch.setattr(pkg, "Scrypt", spy)
    path = _raw_package(tmp_path, {**GOOD_HEADER, **change})
    with pytest.raises(PackageError):
        extract_package(path, tmp_path / "target", PASSWORD)
    assert calls == []


def test_oversized_header_length_is_refused(tmp_path):
    path = _raw_package(tmp_path, GOOD_HEADER, header_len=2**31)
    with pytest.raises(PackageError, match="header"):
        extract_package(path, tmp_path / "target", PASSWORD)


def test_package_size_limit_is_checked_before_reading(tmp_path, source, monkeypatch):
    package_path = create_package(source, tmp_path / "out.pkg", PASSWORD, {})
    monkeypatch.setattr(pkg, "MAX_PACKAGE_BYTES", package_path.stat().st_size - 1)

    def no_read(self):
        raise AssertionError("the file must not be read")

    monkeypatch.setattr(pkg.Path, "read_bytes", no_read)
    with pytest.raises(PackageError, match="larger than"):
        extract_package(package_path, tmp_path / "target", PASSWORD)


def test_create_refuses_a_package_that_extract_would_refuse(tmp_path, source, monkeypatch):
    monkeypatch.setattr(pkg, "MAX_PACKAGE_BYTES", 10)
    with pytest.raises(PackageError, match="larger than"):
        create_package(source, tmp_path / "out.pkg", PASSWORD, {})
    assert not (tmp_path / "out.pkg").exists()


def test_a_file_that_grows_after_stat_is_read_with_a_hard_limit(tmp_path, monkeypatch):
    path = tmp_path / "growing.pkg"
    path.write_bytes(b"x")
    monkeypatch.setattr(pkg, "MAX_PACKAGE_BYTES", 64)
    sizes = []
    original_open = Path.open

    class GrowingFile(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    def open_grown(self, *args, **kwargs):
        if self == path:
            return GrowingFile(b"x" * 128)
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_grown)
    with pytest.raises(PackageError, match="larger than"):
        extract_package(path, tmp_path / "out", PASSWORD)
    assert sizes == [65]
    assert not (tmp_path / "out").exists()


def test_complete_oversized_header_is_rejected_before_scrypt(tmp_path, monkeypatch):
    header = json.dumps(GOOD_HEADER).encode().ljust(pkg.MAX_HEADER_BYTES + 1, b" ")
    path = tmp_path / "large-header.pkg"
    path.write_bytes(pkg.MAGIC + len(header).to_bytes(4, "big") + header + b"x" * 32)
    calls = []

    def spy(**kwargs):
        calls.append(kwargs)
        raise AssertionError("unvalidated header reached scrypt")

    monkeypatch.setattr(pkg, "Scrypt", spy)
    with pytest.raises(PackageError, match="header"):
        extract_package(path, tmp_path / "out", PASSWORD)
    assert calls == []
