# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

"""Deterministic known-answer tests for the artcrypt SM4-Camellia-AES-CBC cascade.

Every input is a transparent sequence -- ``bytes(range(...))``, ``0x10``-style
counters, or the ASCII string "0123..." -- and no test touches ``os.urandom``.
Every expected value is a hard-coded constant, so a mismatch means the on-disk
format, the HKDF labels, the cascade order, the padding or the KDF parameters
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

HEADER_SIZE = len(A.MAGIC) + A.SALT_SIZE + A.IV_SIZE

# --- known answers, captured once and pinned here -------------------------
# Argon2id(time_cost=3, memory_cost=65536, parallelism=4, hash_len=48) over PASSWORD/SALT.
MASTER_KEY_HEX = "2f27df30a156a1cd7cb0e71b96f3a6c0e1bfeca855b452bce08b05a1706e942fc50acd01ed58ff686f06d2f35266bc7d"
# HKDF-SHA-512 expansion of MASTER_KEY_HEX under MASTER_IV.
KEY_MATERIAL = {
    "k_sm4": "577c90be8aba6ecb519e35f4d8dcaf05",
    "k_camellia": "698d3258f546b3491b4fd7b134d98c6b",
    "k_aes": "94ba021f19c5becd276c48fbae1d58a9",
    "k_mac": "adf426b8a72dfde787d4bf2ef543652b10490ad263b0d4161a1e52e77ca14ddb",
    "iv_sm4": "de16cb8b7dcbd320630a79610d94117d",
    "iv_camellia": "239d2eec3ac82ff78a8ed707eb8c1745",
    "iv_aes": "0a8678637f877cfb8b41aeadb86f72da",
}
# Whole encrypted file for PLAINTEXT: MAGIC || SALT || MASTER_IV || 48-byte
# ciphertext (32 bytes plaintext + one PKCS#7 block) || 32-byte KMAC256 tag.
FILE_VECTOR_32 = bytes.fromhex(
    "8941525443595054"  # MAGIC b"\x89ARTCYPT"
    "000102030405060708090a0b0c0d0e0f"  # SALT
    "101112131415161718191a1b1c1d1e1f"  # MASTER_IV
    "296d27de966f2cd0b7c337e8ecf223e8"  # ciphertext block 1
    "d4666552ae4a925bfe3eebfe9c3b0be5"  # ciphertext block 2
    "640c7d54989a15f42c1310ab130a181c"  # ciphertext block 3 (padding)
    "c12abb5a9390081eabab6583ce012e2c"  # KMAC256 tag
    "213df38c3f0410e0968d86079ff2ed69"
)
# Whole encrypted file for the empty plaintext (one all-0x10 padding block).
FILE_VECTOR_EMPTY = bytes.fromhex(
    "8941525443595054"
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "5ed7a79fead379a8cddb4c91bd483f31"
    "1f2dd0bb25670fbb7a0ea67ef8533a02"
    "e1cd766515b74413115ae48a206a3b6b"
)


def padded_len(n: int) -> int:
    """Ciphertext length for an n-byte plaintext: PKCS#7 always adds 1..16 bytes."""
    return A.BLOCK_SIZE * (n // A.BLOCK_SIZE + 1)


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


def test_hkdf_key_material() -> None:
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
    assert blob[len(A.MAGIC) : len(A.MAGIC) + A.SALT_SIZE] == SALT
    assert blob[HEADER_SIZE - A.IV_SIZE : HEADER_SIZE] == MASTER_IV
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


def test_too_small(harness: Harness) -> None:
    harness.rejects(A.MAGIC + bytes(8), "too small")


def test_not_block_aligned(harness: Harness) -> None:
    blob = FILE_VECTOR_32[:HEADER_SIZE] + bytes(17) + FILE_VECTOR_32[-A.TAG_SIZE :]
    harness.rejects(blob, "block-aligned")
