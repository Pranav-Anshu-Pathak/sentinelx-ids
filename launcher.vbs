Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get the project root (same folder as this script)
strRoot = objFSO.GetParentFolderName(WScript.ScriptFullName)

' ── Kill any previous instances on ports 8000 / 5173 ────────────────────────
objShell.Run "cmd /c for /f ""tokens=5"" %a in ('netstat -ano ^| findstr "":8000"" ^| findstr ""LISTENING""') do taskkill /PID %a /F", 0, True
objShell.Run "cmd /c for /f ""tokens=5"" %a in ('netstat -ano ^| findstr "":5173"" ^| findstr ""LISTENING""') do taskkill /PID %a /F", 0, True
WScript.Sleep 1500

' ── Start Backend (Python/Uvicorn) ──────────────────────────────────────────
strPython = strRoot & "\.venv\Scripts\python.exe"
strBackendCmd = """" & strPython & """ -m backend.main"
objShell.CurrentDirectory = strRoot
objShell.Run strBackendCmd, 0, False   ' 0 = hidden window, False = don't wait

' Wait 4 seconds for backend to initialise before starting frontend
WScript.Sleep 4000

' ── Start Frontend (Vite dev server) ────────────────────────────────────────
strNode = "C:\Program Files\nodejs\npm.cmd"
strFrontendDir = strRoot & "\frontend"
strFrontendCmd = """" & strNode & """ run dev"
objShell.CurrentDirectory = strFrontendDir
objShell.Run strFrontendCmd, 0, False  ' 0 = hidden window, False = don't wait

' Wait 5 seconds for Vite to be ready, then open browser
WScript.Sleep 5000
objShell.Run "http://localhost:5173", 1, False
