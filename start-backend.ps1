# Start SentinelX IDS backend
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
    & $python -m pip install -r requirements.txt
}

Write-Host "Starting backend at http://localhost:8000"
& $python -m backend.main
