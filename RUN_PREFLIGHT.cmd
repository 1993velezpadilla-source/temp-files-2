@echo off
setlocal
cd /d "%~dp0"
echo.
echo === WiFi Security Lab - PRECHECK ===
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [FAIL] Python was not found on PATH.
  exit /b 2
)
if "%~1"=="" (
  python wifi_lab.py preflight
) else (
  python wifi_lab.py preflight --capture "%~1"
)
set ERR=%ERRORLEVEL%
echo.
if "%ERR%"=="0" (
  echo [OK] Preflight completed without blockers.
) else (
  echo [CHECK] Preflight reported blockers. Review the output above.
)
exit /b %ERR%
