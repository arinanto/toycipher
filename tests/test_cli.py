# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

"""CLI tests: the operation is a required subcommand and is never inferred.

These cover the behaviour that motivated the explicit mode: a file named
``*.artcrypt`` is just a file, and decrypting a file with any other name is
equally fine. No randomness is involved beyond the salt/IV that ``main()``
draws itself -- the assertions are all about names, exit codes and roundtrips.
"""

import sys
from pathlib import Path

import pytest

from toycipher import artcrypt as A

PASSWORD = "0123456789abcdef0123456789abcdef"
PLAINTEXT = b"0123456789abcdef0123456789abcdef"


def run(monkeypatch: pytest.MonkeyPatch, cwd: Path, *argv: str) -> None:
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("ARTCRYPT_PASSWORD", raising=False)
    monkeypatch.setattr(sys, "argv", ["toycipher", *argv])
    A.main()


def test_mode_is_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, tmp_path)
    assert exc.value.code == 2


def test_filename_is_not_a_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # A bare path must not be interpreted as an operation, whatever it is called.
    for name in ("data.bin", "data.bin.artcrypt"):
        (tmp_path / name).write_bytes(PLAINTEXT)
        with pytest.raises(SystemExit) as exc:
            run(monkeypatch, tmp_path, name)
        assert exc.value.code == 2


def test_encrypt_then_decrypt_with_default_names(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(PLAINTEXT)

    run(monkeypatch, tmp_path, "encrypt", "data.bin", "-p", PASSWORD)
    assert (tmp_path / "data.bin.artcrypt").exists()

    out = tmp_path / "out"
    out.mkdir()
    run(monkeypatch, out, "decrypt", str(tmp_path / "data.bin.artcrypt"), "-p", PASSWORD)
    assert (out / "data.bin").read_bytes() == PLAINTEXT


def test_decrypt_ignores_the_extension(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(PLAINTEXT)
    run(monkeypatch, tmp_path, "encrypt", "data.bin", "-p", PASSWORD)

    # Rename the ciphertext so its name says nothing about its contents.
    (tmp_path / "data.bin.artcrypt").rename(tmp_path / "blob.dat")
    run(monkeypatch, tmp_path, "decrypt", "blob.dat", "-p", PASSWORD)
    assert (tmp_path / "blob.dat.dec").read_bytes() == PLAINTEXT


def test_encrypt_ignores_the_extension(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "inner.artcrypt").write_bytes(PLAINTEXT)
    run(monkeypatch, tmp_path, "encrypt", "inner.artcrypt", "-p", PASSWORD)

    blob = (tmp_path / "inner.artcrypt.artcrypt").read_bytes()
    assert blob.startswith(A.MAGIC)
    assert blob != PLAINTEXT


def test_identical_paths_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "data.bin").write_bytes(PLAINTEXT)
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, tmp_path, "encrypt", "data.bin", "-o", "data.bin", "-p", PASSWORD)
    assert exc.value.code == 1
    assert "identical" in capsys.readouterr().err


def test_wrong_password_exits_without_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(PLAINTEXT)
    run(monkeypatch, tmp_path, "encrypt", "data.bin", "-p", PASSWORD)

    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, tmp_path, "decrypt", "data.bin.artcrypt", "-o", "bad.out", "-p", "nope")
    assert exc.value.code == 1
    assert not (tmp_path / "bad.out").exists()
