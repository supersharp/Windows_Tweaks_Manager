@echo off
setlocal EnableExtensions DisableDelayedExpansion
Title Windows Tweaks Manager Launcher

:: ---------------------------------------------------------
:: 1. CHECK FOR ADMINISTRATOR RIGHTS
:: ---------------------------------------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo  =============================================================
    echo   [!] Administrator privileges required.
    echo   [!] Requesting elevation...
    echo  =============================================================
    echo.
    
    :: Relaunch this specific batch file with Admin rights
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

:: ---------------------------------------------------------
:: 2. SET WORKING DIRECTORY
:: ---------------------------------------------------------
:: Navigate to the folder where this script is located
cd /d "%~dp0"

:: ---------------------------------------------------------
:: 3. RUN POWERSHELL SCRIPT
:: ---------------------------------------------------------
echo.
echo  [+] Launching Windows Tweaks Manager...
echo.

:: Check if the file actually exists before running
if not exist "Windows_Tweaks_Manager.ps1" (
    echo.
    echo  [ERROR] "Windows_Tweaks_Manager.ps1" not found!
    echo  Please ensure the .bat and .ps1 files are in the same folder.
    echo.
    pause
    exit /b
)

:: Run the script with Bypass policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Windows_Tweaks_Manager.ps1"

:: ---------------------------------------------------------
:: 4. EXIT HANDLING
:: ---------------------------------------------------------
:: Pause only if there was a crash, otherwise close cleanly
if %errorLevel% neq 0 (
    echo.
    echo  [ERROR] The script exited with an error code.
    pause
)