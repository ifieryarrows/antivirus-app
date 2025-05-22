# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

# malware_hashes.txt dosyası varsa ekle
extra_files = []
if os.path.exists('malware_hashes.txt'):
    extra_files.append(('malware_hashes.txt', '.'))

a = Analysis(
    ['gui_app.py'],
    pathex=[],
    binaries=[],
    datas=[('icons/*', 'icons/'), ('config.json', '.')] + extra_files,
    hiddenimports=['PIL._tkinter_finder'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ModernAntivirus',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icons/scan.png',
) 