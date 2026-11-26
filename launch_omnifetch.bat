@echo off
setlocal
cd /d "%~dp0"

if exist "%~dp0dist\OmniFetch\OmniFetch.exe" (
    start "" "%~dp0dist\OmniFetch\OmniFetch.exe" %*
) else (
    start "" "%~dp0.venv\Scripts\python.exe" "%~dp0app\main.py" %*
)
exit /b 0
