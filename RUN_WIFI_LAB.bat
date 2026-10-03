@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on PATH.
  exit /b 1
)

if "%~1"=="" (
  python wifi_lab.py interactive
  exit /b %errorlevel%
)

if /I "%~1"=="readiness" (
  python wifi_lab.py readiness --report readiness.json
  exit /b %errorlevel%
)

if /I "%~1"=="scan" (
  python wifi_lab.py scan --report scan_report.json
  exit /b %errorlevel%
)

if /I "%~1"=="diag" (
  python wifi_lab.py diag --report diagnostics.json
  exit /b %errorlevel%
)

if /I "%~1"=="bundle" (
  shift
  python wifi_lab_bundle.py %*
  exit /b %errorlevel%
)

python wifi_lab.py %*
