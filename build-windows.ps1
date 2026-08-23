# Builds a single-file Windows executable of the BlankTrail demo:
# dist\blanktrail-demo.exe, no Python required to run it.
#
# Usage (from the repository root):
#   .\build-windows.ps1
#
# PyInstaller is a build-time tool only. It lives in requirements-build.txt,
# never in requirements.txt, which lists what the demo needs at runtime.

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path ".venv")) {
    Write-Host "Creating a virtual environment..."
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { Write-Error "python -m venv failed"; exit 1 }
}

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

Write-Host "Installing runtime dependencies..."
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Error "pip install -r requirements.txt failed"; exit 1 }

Write-Host "Installing the build tool (PyInstaller)..."
& $venvPython -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { Write-Error "pip install -r requirements-build.txt failed"; exit 1 }

Write-Host "Building blanktrail-demo.exe..."

# --add-data ships the web UI's static files (index.html, app.js, style.css)
# inside the bundle; webui.py finds them under sys._MEIPASS at run time when
# frozen. The rest of the flags below force in runtime dependencies that
# PyInstaller's static analysis does not reliably find on its own: certifi's
# cacert.pem is a data file, not code; truststore, brotli, zstandard and
# backports.zstd are only ever imported from inside try/except blocks in
# third-party code; and PySocks (socks), h2, hpack, hyperframe and socksio
# are imported by name deep inside httpx/requests/urllib3. Without all of
# them the exe still runs, but silently gives wrong answers instead of
# failing loudly -- see the comments in requirements.txt.
& $venvPython -m PyInstaller `
    --name blanktrail-demo `
    --onefile `
    --clean `
    --noconfirm `
    --specpath build `
    --add-data "$PSScriptRoot\blanktrail_demo\assets;blanktrail_demo\assets" `
    --collect-data certifi `
    --collect-all truststore `
    --collect-all brotli `
    --collect-all zstandard `
    --collect-all backports.zstd `
    --hidden-import socks `
    --hidden-import h2 `
    --hidden-import hpack `
    --hidden-import hyperframe `
    --hidden-import socksio `
    build_entry.py
if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller build failed"; exit 1 }

$exe = Join-Path $PSScriptRoot "dist\blanktrail-demo.exe"
if (-not (Test-Path $exe)) {
    Write-Error "build finished but $exe was not produced"
    exit 1
}

$sizeMb = [Math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host ""
Write-Host "Built $exe ($sizeMb MB)"
Write-Host "It runs standalone -- no Python, no venv, no requirements.txt on the target machine."
