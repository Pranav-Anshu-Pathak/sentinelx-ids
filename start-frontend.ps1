# Start SentinelX IDS frontend (adds Node.js to PATH)
$ErrorActionPreference = "Stop"
$env:Path = "C:\Program Files\nodejs;" + $env:Path

Set-Location (Join-Path $PSScriptRoot "frontend")

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js not found. Install from https://nodejs.org/"
    exit 1
}

if (-not (Test-Path node_modules)) {
    Write-Host "Installing frontend dependencies..."
    npm install
}

Write-Host "Starting UI at http://localhost:5173"
npm run dev
