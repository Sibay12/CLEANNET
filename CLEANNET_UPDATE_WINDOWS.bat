@echo off
setlocal EnableExtensions
title CLEANNET ESP32-C3 One-Command Update

echo.
echo ============================================
echo   CLEANNET ESP32-C3 - ONE COMMAND UPDATE
echo   Firmware target: 0.3.2 / one RGB pixel
echo ============================================
echo.

where git >nul 2>nul
if errorlevel 1 (echo ERROR: Git not found. Install Git for Windows.& pause& exit /b 1)
where idf.py >nul 2>nul
if errorlevel 1 (
  echo ERROR: idf.py not found.
  echo Open the ESP-IDF 5.5.x Command Prompt first, then run this file.
  pause
  exit /b 1
)

cd /d "%~dp0"
echo [1/5] Updating source from GitHub main...
git pull --ff-only origin main
if errorlevel 1 (echo ERROR: Git update failed. Resolve local changes before continuing.& pause& exit /b 1)

cd /d "%~dp0firmware\esp32c3"
if not exist "CMakeLists.txt" (echo ERROR: firmware project folder missing.& pause& exit /b 1)

echo.
echo [2/5] Selecting ESP32-C3 target...
idf.py set-target esp32c3
if errorlevel 1 (echo ERROR: set-target failed.& pause& exit /b 1)

echo.
echo [3/5] Building firmware...
idf.py build
if errorlevel 1 (echo ERROR: Build failed. Board has NOT been flashed.& pause& exit /b 1)

echo.
echo BUILD SUCCESS. Firmware is ready.
echo Current firmware image:
echo %CD%\build\cleannet_esp32c3_dns.bin
echo.
set /p PORT=Enter ESP32-C3 COM port (example COM4), or press ENTER to stop:
if "%PORT%"=="" (echo Build completed only. No device was changed.& pause& exit /b 0)

echo.
echo [4/5] Backing up the full 4MB flash before writing...
python -m esptool --chip esp32c3 -p %PORT% -b 460800 read_flash 0 0x400000 "%~dp0cleannet_before_update_4mb.bin"
if errorlevel 1 (
  echo WARNING: Flash backup failed. Firmware will NOT be flashed.
  echo Check COM port, USB cable, and close Serial Monitor.
  pause
  exit /b 1
)

echo.
echo [5/5] Flashing and opening serial monitor...
echo Do not unplug the board during this operation.
idf.py -p %PORT% flash monitor
if errorlevel 1 (
  echo Flash/monitor reported an error. Keep the backup file safe.
  pause
  exit /b 1
)

echo.
echo Serial monitor closed. Check boot log for firmware 0.3.2 and absence of task_wdt errors.
pause
endlocal
