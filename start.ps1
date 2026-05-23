# Start both backend and frontend in separate windows
$root = $PSScriptRoot
Start-Process powershell -ArgumentList "-NoExit", "-File", "`"$root\start-backend.ps1`""
Start-Sleep -Seconds 3
Start-Process powershell -ArgumentList "-NoExit", "-File", "`"$root\start-frontend.ps1`""
Write-Host "Opened backend and frontend terminals."
Write-Host "Open http://localhost:5173 in your browser (login: admin / sentinelx)"
