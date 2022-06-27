# -*- mode: python ; coding: utf-8 -*-

import os
import importlib

# Find the dat file required by fido2 and cause it to be installed.
#
datas = [
    (os.path.join(
        os.path.dirname(importlib.import_module('fido2').__file__),
        'public_suffix_list.dat'),
     'fido2')
    ]

block_cipher = None


a = Analysis(['../alohomora/main.py'],
             pathex=['specs'],
             binaries=[],
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='alohomora',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
