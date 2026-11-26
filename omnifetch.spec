# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
project_root = Path(SPECPATH).resolve()

datas = [
    (str(project_root / 'app' / 'assets'), 'app/assets'),
    (str(project_root / 'app' / 'integrations' / 'cybershield_cli.js'), 'app/integrations'),
    (str(project_root / 'browser_extension'), 'browser_extension'),
] + collect_data_files('certifi')

hiddenimports = [
    'PySide6.QtNetwork',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'aiohttp',
    'aiohttp.web',
    'libtorrent',
    'Crypto',
    'Crypto.Cipher.AES',
    'Crypto.Util.Padding',
    'certifi',
] + collect_submodules('app')

a = Analysis(
    [str(project_root / 'app' / 'main.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'pytest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='OmniFetch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / 'app' / 'assets' / 'omnifetch.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='OmniFetch',
)
