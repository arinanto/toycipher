# -*- mode: python ; coding: utf-8 -*-
# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

import sys
from pathlib import Path

# PyInstaller does not bundle the abi3t-compat stub as of 6.22.3
# (pyinstaller#9562). On Windows, cryptography and argon2-cffi-bindings ship a
# single cp315 wheel tagged "abi3.abi3t" - PEP 803's shared wheel for the GIL
# and free-threaded builds - and its .pyd files import python3t.dll. The stub
# only forwards exports to python315.dll, so shipping it costs 60 KB and
# nothing else. Without it the frozen exe dies on `import cryptography` with
# "DLL load failed while importing _ffi".
#
# A GIL-enabled CPython 3.15 does not put it next to python315.dll: both the
# python.org installer and the GitHub Actions toolcache keep it in an
# abi3t-compat/ subdirectory, out of the loader's default search path, which is
# the same reason PyInstaller cannot find it. The free-threaded build does lay
# it down at the install root. Drop this block once PyInstaller ships the fix
# (changelogged for the release after 6.22.3).
binaries = []
if sys.platform == "win32":
    base = Path(sys.base_prefix)
    abi3t_stubs = [base / "abi3t-compat" / "python3t.dll", base / "python3t.dll"]
    abi3t_stub = next((stub for stub in abi3t_stubs if stub.is_file()), None)
    if abi3t_stub is None:
        checked = ", ".join(map(str, abi3t_stubs))
        raise SystemExit(f"no python3t.dll in {checked}: the abi3t wheels would not load")
    binaries.append((str(abi3t_stub), "."))


a = Analysis(
    ['src/toycipher/__main__.py'],
    pathex=['src'],
    binaries=binaries,
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='toycipher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
