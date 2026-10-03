@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo.
echo === WiFi Security Lab - EXAM RUN ===
echo.
if "%~1"=="" (
  echo Usage:
  echo   RUN_EXAM.cmd "SSID_NAME" [capture.pcapng]
  echo.
  echo Example:
  echo   RUN_EXAM.cmd "Professor_AP" exam.pcapng
  exit /b 2
)
set "SSID=%~1"
set "CAP=%~2"
if "%CAP%"=="" (
  python wifi_lab.py exam-run --ssid "%SSID%"
) else (
  python wifi_lab.py exam-run --ssid "%SSID%" --capture "%CAP%"
)
set ERR=%ERRORLEVEL%
echo.
if "%ERR%"=="0" (
  echo [OK] Exam run completed.
  echo Check wifi_exam_bundleexam_bundle.html
) else (
  echo [CHECK] Exam run returned code %ERR%.
)
exit /b %ERR%
