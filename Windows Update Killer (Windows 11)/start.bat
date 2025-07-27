@echo off
:: start.bat - launches KILL_WINDOWS_UPDATE.ps1 as administrator and keeps the console open

:: Check if the script is run as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Relaunching with administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Launch PowerShell script from the same directory
cd /d "%~dp0"
echo Starting KILL_WINDOWS_UPDATE.ps1...
powershell -NoExit -ExecutionPolicy Bypass -File "KILL_WINDOWS_UPDATE.ps1"
