@echo off
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
where pythonw >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pythonw not found. Install Python 3.8+ and check "Add Python to PATH".
    pause
    exit /b
)
start "" pythonw "%~dp0yk_modifier.py"
