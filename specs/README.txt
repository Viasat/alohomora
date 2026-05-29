The alohomora.spec file herein can be used to by PyInstaller to build a self-contained
alhomora EXE.

Usage
From an elevated PowerShell prompt at the repo root:

What it does
Detects Python 3 via py / python / python3; if missing, installs it through winget (Python.Python.3.12 by default) and refreshes PATH for the current session.
Creates .venv\ at the repo root (reuses it on subsequent runs unless -Clean is passed).
Installs .[fido2] plus pyinstaller into the venv.
Runs pyinstaller --clean --noconfirm specs\alohomora.spec.
Prints the resulting dist\alohomora.exe path.
Requires winget only if Python is not already installed; otherwise the script runs without admin.