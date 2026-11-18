# -*- mode: python ; coding: utf-8 -*-
# Copyright (C) 2026 Rinaldi Widianto
# SPDX-License-Identifier: AGPL-3.0-only

import sys
from pathlib import Path

# PyInstaller 6.22 does not bundle the abi3t-compat stub (pyinstaller#9562).
# On Windows, cryptography and argon2-cffi-bindings ship a single cp315 wheel
# tagged "abi3.abi3t" - PEP 803's shared wheel for the GIL and free-threaded
# builds - and its .pyd files import python3t.dll. A GIL CPython 3.15 install
# lays that stub down next to python315.dll; it only forwards exports to
# python315.dll, so shipping it costs 60 KB and nothing else. Without it the
# frozen exe dies on `import cryptography` with "DLL load failed while
# importing _ffi". Drop this block once PyInstaller bundles the stub itself.
binaries = []
if sys.platform == "win32":
    abi3t_stub = Path(sys.base_prefix) / "python3t.dll"
    if not abi3t_stub.is_file():
        raise SystemExit(f"{abi3t_stub} is missing: the abi3t wheels would not load")
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
