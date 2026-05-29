<#
.SYNOPSIS
    Bootstraps a Windows machine and builds a self-contained alohomora.exe
    using PyInstaller.

.DESCRIPTION
    Steps performed:
      1. Ensures Python 3 is available (installs it via winget if missing).
      2. Creates a clean virtual environment in .venv at the repo root.
      3. Installs alohomora (with the fido2 extra) and PyInstaller.
      4. Runs PyInstaller against specs\alohomora.spec.
      5. Reports the path to the resulting EXE.

    Run from an elevated PowerShell prompt the first time (so Python can be
    installed). Subsequent rebuilds do not require admin rights.

.PARAMETER PythonVersion
    The Python 3 version to install via winget if Python is not present.
    Defaults to 3.12.

.PARAMETER Clean
    Wipe the existing .venv, build, and dist directories before building.

.EXAMPLE
    PS> .\specs\build-windows.ps1

.EXAMPLE
    PS> .\specs\build-windows.ps1 -Clean
#>

[CmdletBinding()]
param(
    [string]$PythonVersion = '3.12',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Resolve repo root (this script lives in <repo>\specs\)
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot
Write-Step "Working directory: $RepoRoot"

# ---------------------------------------------------------------------------
# 1. Ensure Python is installed
# ---------------------------------------------------------------------------
function Get-PythonExe {
    $candidates = @('py', 'python', 'python3')
    foreach ($cmd in $candidates) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) {
            try {
                $ver = & $found.Source --version 2>&1
                if ($ver -match 'Python\s+3\.') {
                    return $found.Source
                }
            } catch { }
        }
    }
    return $null
}

Write-Step "Checking for Python 3"
$python = Get-PythonExe

if (-not $python) {
    Write-Host "Python 3 not found. Attempting to install via winget..." -ForegroundColor Yellow
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "winget is not available. Please install Python 3 manually from https://www.python.org/downloads/windows/ and re-run this script."
    }

    $pkgId = "Python.Python.$PythonVersion"
    winget install --id $pkgId --source winget --accept-source-agreements --accept-package-agreements -e
    if ($LASTEXITCODE -ne 0) {
        throw "winget failed to install $pkgId (exit code $LASTEXITCODE)."
    }

    # Refresh PATH for this session so the new python.exe is discoverable.
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')

    $python = Get-PythonExe
    if (-not $python) {
        throw "Python install appeared to succeed but no python executable is on PATH. Open a new shell and re-run this script."
    }
}

Write-Host "Using Python: $python"
& $python --version

# ---------------------------------------------------------------------------
# 2. Clean previous build artifacts if requested
# ---------------------------------------------------------------------------
if ($Clean) {
    Write-Step "Cleaning .venv, build, dist"
    foreach ($dir in @('.venv', 'build', 'dist')) {
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    }
}

# ---------------------------------------------------------------------------
# 3. Create / activate virtual environment
# ---------------------------------------------------------------------------
$VenvDir    = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

if (-not (Test-Path $VenvPython)) {
    Write-Step "Creating virtual environment at $VenvDir"
    & $python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to create virtual environment." }
} else {
    Write-Step "Reusing existing virtual environment at $VenvDir"
}

# ---------------------------------------------------------------------------
# 4. Install dependencies
# ---------------------------------------------------------------------------
Write-Step "Upgrading pip / setuptools / wheel"
& $VenvPython -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }

Write-Step "Installing alohomora (with fido2 extra) and PyInstaller"
& $VenvPython -m pip install ".[fido2]" pyinstaller
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

# ---------------------------------------------------------------------------
# 5. Run PyInstaller
# ---------------------------------------------------------------------------
$SpecFile = Join-Path $ScriptDir 'alohomora.spec'
if (-not (Test-Path $SpecFile)) { throw "Spec file not found: $SpecFile" }

Write-Step "Running PyInstaller against $SpecFile"
& $VenvPython -m PyInstaller --clean --noconfirm $SpecFile
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

# ---------------------------------------------------------------------------
# 6. Report result
# ---------------------------------------------------------------------------
$ExePath = Join-Path $RepoRoot 'dist\alohomora.exe'
if (Test-Path $ExePath) {
    Write-Step "Build complete"
    Write-Host "Executable: $ExePath" -ForegroundColor Green
    Write-Host "Test it with: .\dist\alohomora.exe --help"
} else {
    throw "Build finished but $ExePath was not produced."
}
