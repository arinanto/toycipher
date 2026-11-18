# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

"""Deterministic known-answer tests for the artcrypt SM4-Camellia-AES-CBC cascade.

Every input is a transparent sequence -- ``bytes(range(...))``, ``0x10``-style
counters, or the ASCII string "0123..." -- and no test touches ``os.urandom``.
Every expected value is a hard-coded constant, so a mismatch means the on-disk
format, the KMAC256 KDF labels, the cascade order, the padding or the KDF parameters
changed, not that the machine got unlucky.

Run with:  uv run pytest
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from toycipher import artcrypt as A

# Transparent, fixed inputs: nothing random anywhere.
PASSWORD = "0123456789abcdef0123456789abcdef"
SALT = bytes(range(16))  # 00 01 02 ... 0f
MASTER_IV = bytes(range(16, 32))  # 10 11 12 ... 1f
PLAINTEXT = b"0123456789abcdef0123456789abcdef"  # 32 ASCII bytes

HEADER_SIZE = A.HEADER_SIZE

# --- known answers, captured once and pinned here -------------------------
# Argon2id(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32) over PASSWORD/SALT.
MASTER_KEY_HEX = "7fc91051dad9212ac204f6ed76c498cac5d5e0c27a623b3cd359bb9d59ac3507"
# KMAC256 expansion of MASTER_KEY_HEX with MASTER_IV as the message.
KEY_MATERIAL = {
    "k_sm4": "fb66b17d3a98afbf82ae2e8e3b366b99",
    "k_camellia": "4b59ecff9fc1c5e435994c35c77e60be",
    "k_aes": "44c827efa599a65100b5bdddf89eb68c",
    "k_mac": "5ec2791a74419769755fabc6363b0c4b5a7e7bf3061e8a6e15f175ef18196078",
    "iv_sm4": "06ca78e4cbf656b7811203c51d8b6744",
    "iv_camellia": "b3c3dbfe59389f91366f020f4ceea047",
    "iv_aes": "5c78c3b96f61db768ff7adfe2cd0f778",
}
# Whole encrypted file for PLAINTEXT: MAGIC || version(2) || length(0x70) || SALT ||
# MASTER_IV || 48-byte ciphertext (32 bytes plaintext + one PKCS#7 block) || 32-byte
# KMAC256 tag. The length counts salt+master_iv+ciphertext+tag = 112 = 0x70 bytes.
FILE_VECTOR_32 = bytes.fromhex(
    "8941525443595054"  # MAGIC b"\x89ARTCYPT"
    "00000002"  # version 2, big-endian
    "0000000000000070"  # length 112, big-endian
    "000102030405060708090a0b0c0d0e0f"  # SALT
    "101112131415161718191a1b1c1d1e1f"  # MASTER_IV
    "2db75a3fe731b9656d06fcfb559ccaaa"  # ciphertext block 1
    "607442713ce40b63cab747bfef3bbf0c"  # ciphertext block 2
    "afb51245efd281f5caecb1115b240b08"  # ciphertext block 3 (padding)
    "7fe54324efd495223872bd19bc7c2770"  # KMAC256 tag
    "d2c1dd82e7d9937641fa507f3daf25e2"
)
# Whole encrypted file for the empty plaintext (one all-0x10 padding block).
# The length counts salt+master_iv+ciphertext+tag = 80 = 0x50 bytes.
FILE_VECTOR_EMPTY = bytes.fromhex(
    "8941525443595054"
    "00000002"
    "0000000000000050"
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "e78ef5401c6870179eb85b16a55956f9"
    "854714f067e87fe692697459dce738c5"
    "8762f119fb3a1e087178c3b39d07a957"
)


def padded_len(n: int) -> int:
    """Ciphertext length for an n-byte plaintext: PKCS#7 always adds 1..16 bytes."""
    return A.BLOCK_SIZE * (n // A.BLOCK_SIZE + 1)


def with_length(body: bytes) -> bytes:
    """A complete file: magic, the current format version and a matching length field."""
    header = A.MAGIC + A.VERSION.to_bytes(A.VERSION_SIZE, "big") + len(body).to_bytes(A.LENGTH_SIZE, "big")
    return header + body


@dataclass
class Harness:
    """Thin file-system driver: every cipher call goes through artcrypt, unmodified."""

    dir: Path

    def encrypt(self, plaintext: bytes, name: str = "ct", password: str = PASSWORD) -> bytes:
        src = self.dir / f"{name}.pt"
        src.write_bytes(plaintext)
        A.encrypt_file(str(src), str(self.dir / name), password, salt=SALT, master_iv=MASTER_IV)
        return (self.dir / name).read_bytes()

    def decrypt(self, blob: bytes, name: str = "pt.out", password: str = PASSWORD) -> bytes:
        src = self.dir / f"{name}.in"
        src.write_bytes(blob)
        A.decrypt_file(str(src), str(self.dir / name), password)
        return (self.dir / name).read_bytes()

    def rejects(self, blob: bytes, match: str, password: str = PASSWORD) -> None:
        src = self.dir / "rejected.in"
        src.write_bytes(blob)
        out = self.dir / "rejected.out"
        with pytest.raises(ValueError, match=match):
            A.decrypt_file(str(src), str(out), password)
        assert not out.exists(), "plaintext was written despite the rejection"


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


# --- known answers -------------------------------------------------------


def test_argon2id_master_key() -> None:
    assert A.derive_master_key(PASSWORD, SALT).hex() == MASTER_KEY_HEX


def test_kmac_key_material() -> None:
    mat = A.expand_cascade_material(bytes.fromhex(MASTER_KEY_HEX), MASTER_IV)
    assert {k: v.hex() for k, v in mat.items()} == KEY_MATERIAL


def test_encrypt_known_answer(harness: Harness) -> None:
    assert harness.encrypt(PLAINTEXT) == FILE_VECTOR_32


def test_decrypt_known_answer(harness: Harness) -> None:
    assert harness.decrypt(FILE_VECTOR_32) == PLAINTEXT


def test_empty_plaintext_known_answer(harness: Harness) -> None:
    assert harness.encrypt(b"", "empty") == FILE_VECTOR_EMPTY
    assert harness.decrypt(FILE_VECTOR_EMPTY, "empty.out") == b""


def test_header_layout(harness: Harness) -> None:
    blob = harness.encrypt(PLAINTEXT, "layout")
    assert blob[: len(A.MAGIC)] == A.MAGIC
    assert blob[len(A.MAGIC) : A.LENGTH_OFFSET] == A.VERSION.to_bytes(A.VERSION_SIZE, "big")
    length_field = int.from_bytes(blob[A.LENGTH_OFFSET : A.LENGTH_OFFSET + A.LENGTH_SIZE], "big")
    assert length_field == len(blob) - A.BODY_OFFSET
    assert blob[A.HEADER_SIZE - A.IV_SIZE - A.SALT_SIZE : A.HEADER_SIZE - A.IV_SIZE] == SALT
    assert blob[A.HEADER_SIZE - A.IV_SIZE : A.HEADER_SIZE] == MASTER_IV
    assert len(blob) == HEADER_SIZE + padded_len(len(PLAINTEXT)) + A.TAG_SIZE


def test_no_hidden_randomness(harness: Harness) -> None:
    # Same password + same salt/IV must give byte-identical output.
    assert harness.encrypt(PLAINTEXT, "a") == harness.encrypt(PLAINTEXT, "b")


# --- padding -------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 33, 64, 1000])
def test_padded_exactly_once(harness: Harness, size: int) -> None:
    # The file grows by exactly one PKCS#7 block, never once per cascade layer.
    plaintext = bytes(i % 256 for i in range(size))
    blob = harness.encrypt(plaintext, f"p{size}")
    assert len(blob) == HEADER_SIZE + padded_len(size) + A.TAG_SIZE
    assert harness.decrypt(blob, f"p{size}.out") == plaintext


@pytest.mark.parametrize("size", [A.CHUNK_SIZE - 1, A.CHUNK_SIZE, A.CHUNK_SIZE + 1])
def test_chunk_boundary_roundtrip(harness: Harness, size: int) -> None:
    plaintext = bytes(i % 256 for i in range(size))
    blob = harness.encrypt(plaintext, f"c{size}")
    assert len(blob) == HEADER_SIZE + padded_len(size) + A.TAG_SIZE
    assert harness.decrypt(blob, f"c{size}.out") == plaintext


# --- rejection -----------------------------------------------------------


def test_wrong_password(harness: Harness) -> None:
    harness.rejects(FILE_VECTOR_32, "Authentication failed", password="fedcba9876543210fedcba9876543210")


def test_tampered_ciphertext(harness: Harness) -> None:
    blob = bytearray(FILE_VECTOR_32)
    blob[HEADER_SIZE + 1] ^= 0x01
    harness.rejects(bytes(blob), "Authentication failed")


def test_tampered_padding_block(harness: Harness) -> None:
    blob = bytearray(FILE_VECTOR_32)
    blob[HEADER_SIZE + len(PLAINTEXT)] ^= 0x80  # last ciphertext block, which holds the padding
    harness.rejects(bytes(blob), "Authentication failed")


def test_tampered_tag(harness: Harness) -> None:
    blob = bytearray(FILE_VECTOR_32)
    blob[-1] ^= 0x01
    harness.rejects(bytes(blob), "Authentication failed")


def test_bad_magic(harness: Harness) -> None:
    harness.rejects(b"\x00" + FILE_VECTOR_32[1:], "bad magic number")


def test_old_format_without_version_field(harness: Harness) -> None:
    # A pre-version file puts the salt right after the magic, so the version field
    # reads a nonzero salt byte and is rejected cheaply instead of authenticating.
    old_blob = FILE_VECTOR_32[: len(A.MAGIC)] + FILE_VECTOR_32[A.BODY_OFFSET :]
    harness.rejects(old_blob, "Unsupported format version")


@pytest.mark.parametrize("version", [0, 1, 3, 0xFFFFFFFF])
def test_unsupported_version(harness: Harness, version: int) -> None:
    blob = bytearray(FILE_VECTOR_32)
    blob[len(A.MAGIC) : A.LENGTH_OFFSET] = version.to_bytes(A.VERSION_SIZE, "big")
    harness.rejects(bytes(blob), f"Unsupported format version {version}")


@pytest.mark.parametrize("delta", [-16, -1, 1, 16])
def test_length_field_mismatch(harness: Harness, delta: int) -> None:
    blob = bytearray(FILE_VECTOR_32)
    claimed = len(blob) - A.BODY_OFFSET + delta
    blob[A.LENGTH_OFFSET : A.LENGTH_OFFSET + A.LENGTH_SIZE] = claimed.to_bytes(A.LENGTH_SIZE, "big")
    harness.rejects(bytes(blob), "length field does not match the file size")


@pytest.mark.parametrize("cut", [1, A.TAG_SIZE, HEADER_SIZE])
def test_truncated_file(harness: Harness, cut: int) -> None:
    harness.rejects(FILE_VECTOR_32[:-cut], "length field does not match the file size")


def test_trailing_byte(harness: Harness) -> None:
    harness.rejects(FILE_VECTOR_32 + b"\x00", "length field does not match the file size")


@pytest.mark.parametrize(
    "blob",
    [
        A.MAGIC + bytes(3),  # version field cut short
        A.MAGIC + A.VERSION.to_bytes(A.VERSION_SIZE, "big") + bytes(4),  # length field cut short
    ],
)
def test_too_small(harness: Harness, blob: bytes) -> None:
    harness.rejects(blob, "too small")


def test_body_below_minimum(harness: Harness) -> None:
    # Valid magic, version and a length that matches the file, but no ciphertext.
    harness.rejects(with_length(SALT + MASTER_IV + FILE_VECTOR_32[-A.TAG_SIZE :]), "too small")


def test_not_block_aligned(harness: Harness) -> None:
    harness.rejects(with_length(SALT + MASTER_IV + bytes(17) + FILE_VECTOR_32[-A.TAG_SIZE :]), "block-aligned")


def test_cheap_checks_never_reach_argon2id(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    # Magic, version and length must all bail before the 64 MiB Argon2id pass.
    # The stub turns a short-circuit failure into a fast, explicit failure.
    def unused_kdf(password: str, salt: bytes) -> bytes:
        raise AssertionError("Argon2id ran despite a failed cheap check")

    monkeypatch.setattr(A, "derive_master_key", unused_kdf)

    bad_version = bytearray(FILE_VECTOR_32)
    bad_version[len(A.MAGIC) : A.LENGTH_OFFSET] = (A.VERSION + 1).to_bytes(A.VERSION_SIZE, "big")
    bad_length = bytearray(FILE_VECTOR_32)
    bad_length[A.LENGTH_OFFSET : A.LENGTH_OFFSET + A.LENGTH_SIZE] = (1).to_bytes(A.LENGTH_SIZE, "big")

    for blob, match in (
        (b"\x00" + FILE_VECTOR_32[1:], "bad magic number"),
        (bytes(bad_version), "Unsupported format version"),
        (bytes(bad_length), "length field does not match"),
    ):
        harness.rejects(blob, match)
