# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import os
import struct
import sys
from typing import BinaryIO

import pwinput
from argon2.low_level import Type, hash_secret_raw
from Crypto.Hash import KMAC256
from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# On-disk layout:
#   MAGIC(8) || version(4) || length(8) || salt(16) || master_iv(16) || ciphertext || tag(32)
# `length` is a big-endian uint64 counting every byte after the field itself, so it
# covers salt, master_iv, ciphertext and tag. Ciphertext is PKCS#7-padded once, so its
# length is always a multiple of BLOCK_SIZE.
MAGIC = b"\x89ARTCYPT"  # 8-byte file signature, written first and checked first
VERSION = 1  # format version; the only value this build writes and accepts
VERSION_SIZE = 4  # big-endian uint32 version field
LENGTH_SIZE = 8  # big-endian uint64 byte count of everything after this field
LENGTH_OFFSET = len(MAGIC) + VERSION_SIZE  # start of the length field
BODY_OFFSET = LENGTH_OFFSET + LENGTH_SIZE  # first byte the length field counts
CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks (multiple of BLOCK_SIZE)
BLOCK_SIZE = 16  # SM4, Camellia and AES all use 128-bit blocks
SALT_SIZE = 16  # 128-bit Argon2id salt
IV_SIZE = 16  # 128-bit Master IV
TAG_SIZE = 32  # 256-bit KMAC256 authentication tag
HEADER_SIZE = BODY_OFFSET + SALT_SIZE + IV_SIZE  # 52 bytes: ciphertext starts here
EXT = ".artcrypt"


def _read_chunk(fin: BinaryIO, size: int) -> bytes:
    """Reads up to `size` bytes, joining short reads. Empty bytes at EOF.

    Short reads are only possible on non-regular files, but joining them keeps
    every update() handed to the CBC contexts block-aligned.
    """
    buf = bytearray()
    while len(buf) < size:
        part = fin.read(size - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def derive_master_key(password: str, salt: bytes) -> bytes:
    """Stretches a password into a 384-bit (48-byte) master key using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=48,
        type=Type.ID,
    )


def expand_cascade_material(master_key: bytes, master_iv: bytes) -> dict[str, bytes]:
    """Expands the 384-bit master key and 128-bit IV using HKDF-SHA-512 (>=384-bit security)."""
    key_material = HKDF(
        algorithm=hashes.SHA512(),
        length=80,
        salt=master_iv,
        info=b"SM4CBC_CAMELLIA128CBC_AES128CBC_KMAC256_KEYS",
    ).derive(master_key)

    iv_material = HKDF(
        algorithm=hashes.SHA512(),
        length=48,
        salt=master_key,
        info=b"SM4CBC_CAMELLIA128CBC_AES128CBC_KMAC256_IVS",
    ).derive(master_iv)

    return {
        "k_sm4": key_material[0:16],
        "k_camellia": key_material[16:32],
        "k_aes": key_material[32:48],
        "k_mac": key_material[48:80],
        "iv_sm4": iv_material[0:16],
        "iv_camellia": iv_material[16:32],
        "iv_aes": iv_material[32:48],
    }


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    *,
    salt: bytes | None = None,
    master_iv: bytes | None = None,
) -> None:
    """Encrypts a file in streaming chunks using SM4-CBC -> Camellia-CBC -> AES-CBC + KMAC256.

    The plaintext is PKCS#7-padded exactly once, before SM4. All three ciphers have
    128-bit blocks, so the padded length is a multiple of 16 and every layer stays
    block-aligned: no intermediate padding, and ciphertext length == padded length.

    `salt` and `master_iv` are injection points for deterministic known-answer tests.
    Real callers must leave them unset, so every encryption gets fresh randomness.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    if master_iv is None:
        master_iv = os.urandom(IV_SIZE)

    master_key = derive_master_key(password, salt)
    mat = expand_cascade_material(master_key, master_iv)

    enc_sm4 = Cipher(algorithms.SM4(mat["k_sm4"]), modes.CBC(mat["iv_sm4"])).encryptor()
    enc_cam = Cipher(Camellia(mat["k_camellia"]), modes.CBC(mat["iv_camellia"])).encryptor()
    enc_aes = Cipher(algorithms.AES(mat["k_aes"]), modes.CBC(mat["iv_aes"])).encryptor()

    mac = KMAC256.new(key=mat["k_mac"], mac_len=TAG_SIZE, custom=b"CASCADE_AUTH_TAG")
    mac.update(salt)
    mac.update(master_iv)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack(">I", VERSION))
        fout.write(bytes(LENGTH_SIZE))  # placeholder, patched once the total is known
        fout.write(salt)
        fout.write(master_iv)

        def emit(padded: bytes) -> None:
            c3 = enc_aes.update(enc_cam.update(enc_sm4.update(padded)))
            if c3:
                mac.update(c3)
                fout.write(c3)

        # The padder holds back a trailing partial block and emits the padding
        # once, at finalize(); an empty file still produces one full block.
        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        while True:
            chunk = _read_chunk(fin, CHUNK_SIZE)
            if not chunk:
                break
            emit(padder.update(chunk))
        emit(padder.finalize())

        tail = enc_sm4.finalize()
        tail = enc_cam.update(tail) + enc_cam.finalize()
        tail = enc_aes.update(tail) + enc_aes.finalize()
        if tail:
            mac.update(tail)
            fout.write(tail)

        fout.write(mac.digest())

        # The length counts everything after the field, so it is only known once the
        # whole body is written. Patching it from the real byte count stays exact
        # even if the input changed size mid-stream. The field is big-endian.
        body_len = fout.tell() - BODY_OFFSET
        fout.seek(LENGTH_OFFSET)
        fout.write(struct.pack(">Q", body_len))


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Verifies KMAC256 tag first, then decrypts in streaming chunks and strips padding."""
    file_size = os.path.getsize(input_path)

    with open(input_path, "rb") as fin:
        # Cheapest possible rejection, in order: signature, version, length. All three
        # bail out before Argon2id, before any crypto, before any output is written.
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not an artcrypt file: bad magic number.")

        raw_version = fin.read(VERSION_SIZE)
        if len(raw_version) < VERSION_SIZE:
            raise ValueError("File is too small or corrupted.")
        if (version := struct.unpack(">I", raw_version)[0]) != VERSION:
            raise ValueError(f"Unsupported format version {version}: this build reads version {VERSION} only.")

        raw_length = fin.read(LENGTH_SIZE)
        if len(raw_length) < LENGTH_SIZE:
            raise ValueError("File is too small or corrupted.")
        body_len = struct.unpack(">Q", raw_length)[0]
        if body_len != file_size - BODY_OFFSET:
            raise ValueError("File is truncated or corrupted: length field does not match the file size.")

        min_body = SALT_SIZE + IV_SIZE + BLOCK_SIZE + TAG_SIZE  # at least one padded block
        if body_len < min_body:
            raise ValueError("File is too small or corrupted.")

        ciphertext_len = body_len - SALT_SIZE - IV_SIZE - TAG_SIZE
        if ciphertext_len % BLOCK_SIZE:
            raise ValueError("File is truncated or corrupted: ciphertext is not block-aligned.")

        salt = fin.read(SALT_SIZE)
        master_iv = fin.read(IV_SIZE)

        master_key = derive_master_key(password, salt)
        mat = expand_cascade_material(master_key, master_iv)

        mac = KMAC256.new(key=mat["k_mac"], mac_len=TAG_SIZE, custom=b"CASCADE_AUTH_TAG")
        mac.update(salt)
        mac.update(master_iv)

        remaining = ciphertext_len
        while remaining > 0:
            chunk = _read_chunk(fin, min(CHUNK_SIZE, remaining))
            if not chunk:
                raise OSError("Unexpected end of file while reading ciphertext.")
            mac.update(chunk)
            remaining -= len(chunk)

        expected_tag = fin.read(TAG_SIZE)
        try:
            mac.verify(expected_tag)
        except ValueError:
            raise ValueError("Authentication failed! Wrong password or tampered file.")

        fin.seek(HEADER_SIZE)
        dec_aes = Cipher(algorithms.AES(mat["k_aes"]), modes.CBC(mat["iv_aes"])).decryptor()
        dec_cam = Cipher(Camellia(mat["k_camellia"]), modes.CBC(mat["iv_camellia"])).decryptor()
        dec_sm4 = Cipher(algorithms.SM4(mat["k_sm4"]), modes.CBC(mat["iv_sm4"])).decryptor()

        # The unpadder likewise holds back the final block and validates the
        # PKCS#7 bytes at the very end of the stream, so it stays streaming-safe.
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()

        with open(output_path, "wb") as fout:

            def emit(padded: bytes) -> None:
                p = unpadder.update(padded)
                if p:
                    fout.write(p)

            remaining = ciphertext_len
            while remaining > 0:
                chunk = _read_chunk(fin, min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise OSError("Unexpected end of file while reading ciphertext.")
                remaining -= len(chunk)
                emit(dec_sm4.update(dec_cam.update(dec_aes.update(chunk))))

            tail = dec_aes.finalize()
            tail = dec_cam.update(tail) + dec_cam.finalize()
            tail = dec_sm4.update(tail) + dec_sm4.finalize()
            fout.write(unpadder.update(tail) + unpadder.finalize())


def _add_mode_args(parser: argparse.ArgumentParser) -> None:
    """Adds the file arguments shared by both modes."""
    parser.add_argument("input_file", help="Path to the input file")
    parser.add_argument("-o", "--output", help="Output path (default: derived name in the current directory)")
    parser.add_argument(
        "-p",
        "--password",
        help="Password for non-interactive use (prefer the ARTCRYPT_PASSWORD env var, "
        "since argv may be visible to other processes)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Builds the CLI: the mode is a required subcommand, never inferred."""
    parser = argparse.ArgumentParser(
        prog="toycipher",
        description="Encrypt or decrypt files with the SM4-Camellia-AES-CBC + KMAC256 cascade.",
    )
    modes = parser.add_subparsers(dest="mode", required=True, metavar="{encrypt,decrypt}")

    enc = modes.add_parser("encrypt", help="Encrypt a file (default output: <name>.artcrypt)")
    _add_mode_args(enc)

    dec = modes.add_parser("decrypt", help="Decrypt a file (default output: <name> minus .artcrypt, else <name>.dec)")
    _add_mode_args(dec)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    input_path = args.input_file
    if not os.path.isfile(input_path):
        print(f"Error: File '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    base_name = os.path.basename(input_path)
    cwd = os.getcwd()

    # The operation comes from the subcommand only. The name is used to pick a
    # default output path, never to decide what to do.
    if args.mode == "encrypt":
        out_name = base_name + EXT
    elif base_name.endswith(EXT):
        out_name = base_name[: -len(EXT)] or "decrypted_output"
    else:
        out_name = base_name + ".dec"

    output_path = args.output if args.output else os.path.join(cwd, out_name)

    if os.path.abspath(input_path) == os.path.abspath(output_path):
        print("Error: Input and output paths are identical.", file=sys.stderr)
        sys.exit(1)

    # Non-interactive password: CLI flag first, then env var, else prompt.
    password = args.password
    if password is None:
        password = os.environ.get("ARTCRYPT_PASSWORD")
    interactive = password is None

    try:
        if interactive:
            password = pwinput.pwinput(prompt="Password: ", mask="*")
        if args.mode == "encrypt":
            if interactive:
                confirm = pwinput.pwinput(prompt="Confirm Password: ", mask="*")
                if password != confirm:
                    print("Error: Passwords do not match.", file=sys.stderr)
                    sys.exit(1)
            if not password:
                print("Error: Password cannot be empty.", file=sys.stderr)
                sys.exit(1)

            print(f"Encrypting -> {output_path}")
            encrypt_file(input_path, output_path, password)
            print("Encryption complete.")
        else:
            print(f"Decrypting -> {output_path}")
            decrypt_file(input_path, output_path, password)
            print("Decryption complete.")

    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        if os.path.exists(output_path):
            os.remove(output_path)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if os.path.exists(output_path):
            os.remove(output_path)
        sys.exit(1)
