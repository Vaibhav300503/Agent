# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:\\Users\\INDIA TECHNOLOGY\\Desktop\\Agent\\soc-agent\\src', 'src')]
binaries = []
hiddenimports = ['win32timezone', 'win32service', 'win32event', 'servicemanager', 'win32serviceutil', 'src', 'src.config', 'src.transport', 'src.collectors', 'src.collectors.windows', 'src.collectors.base', 'uuid', 'psutil', 'watchdog']
tmp_ret = collect_all('pywin32')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('win32')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('win32ctypes')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:\\Users\\INDIA TECHNOLOGY\\Desktop\\Agent\\soc-agent\\src\\service_windows.py'],
    pathex=['C:\\Users\\INDIA TECHNOLOGY\\Desktop\\Agent\\soc-agent'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='SocAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SocAgent',
)
