@echo off
:: ShadowNet Nexus - Auto-Elevate to Administrator
:: This script automatically requests admin privileges

echo.
echo ========================================
echo   ShadowNet Nexus v3.0
echo   Proactive Evidence Preservation
echo ========================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
    echo.
    goto :run_shadownet
) else (
    echo [!] Administrator privileges required
    echo [!] Requesting elevation...
    echo.
    
    :: Re-launch with admin privileges
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run_shadownet
echo Starting ShadowNet Nexus...
echo.

:: Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call venv\Scripts\activate.bat
)

:: Run ShadowNet
echo [*] Launching ShadowNet Nexus Core Engine...
echo.
python shadownet_nexus.py

:: Keep window open if there's an error
if %errorLevel% NEQ 0 (
    echo.
    echo ========================================
    echo   ERROR: ShadowNet failed to start
    echo ========================================
    echo.
    pause
)

exit /b
