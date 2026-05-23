@echo off
echo Stopping SentinelX IDS...

:: Kill backend (port 8000)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Kill frontend (port 5173)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5173" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Kill any remaining python / node processes related to sentinelx (optional)
:: taskkill /IM python.exe /F >nul 2>&1
:: taskkill /IM node.exe /F >nul 2>&1

echo SentinelX IDS stopped.
timeout /t 2 >nul
