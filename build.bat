@echo off
setlocal

REM ============================================================
REM  PS Payload Injector - Build Script
REM  Compiles payload_injector.py into a standalone .exe.
REM  No separate Python install is needed on the target PC - the
REM  interpreter and all PySide6/Qt dependencies are embedded in
REM  the .exe. Built for 64-bit Windows 10/11 (covers virtually
REM  all modern PCs). Antivirus/SmartScreen may still flag or
REM  delete it on first run since it's an unsigned PyInstaller exe -
REM  that's expected, not a sign the build is broken.
REM ============================================================

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "VENV_DIR=%PROJECT_DIR%\build_venv"

cd /d "%PROJECT_DIR%" || (
    echo [ERROR] Could not find project folder:
    echo   %PROJECT_DIR%
    pause
    exit /b 1
)

echo ============================================================
echo  Checking required files are present...
echo ============================================================
set "MISSING=0"
if not exist "payload_injector.py" (
    echo [MISSING] payload_injector.py
    set "MISSING=1"
)
if not exist "icon.ico" (
    echo [MISSING] icon.ico  ^(copy it into this folder: %PROJECT_DIR%^)
    set "MISSING=1"
)
if not exist "data\payloads" (
    echo [MISSING] data\payloads folder
    set "MISSING=1"
)
if "%MISSING%"=="1" (
    echo.
    echo [ERROR] One or more required files are missing from the project
    echo         folder above. Restore them, then re-run this script.
    pause
    exit /b 1
)
echo  All required files found.

echo ============================================================
echo  Creating clean virtual environment for the build...
echo  (keeps the .exe free of unrelated packages so it stays
echo   small and works correctly on other PCs)
echo ============================================================
if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
python -m venv "%VENV_DIR%" || (
    echo [ERROR] Failed to create virtual environment. Is Python installed and on PATH?
    pause
    exit /b 1
)

call "%VENV_DIR%\Scripts\activate.bat"

echo.
echo ============================================================
echo  Installing only the dependencies this app needs...
echo ============================================================
python -m pip install --upgrade pip >nul
python -m pip install --upgrade pyinstaller PySide6

echo.
echo ============================================================
echo  Cleaning previous build artifacts...
echo ============================================================
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist PS-Payload-Injector_v1.1.spec del /q PS-Payload-Injector_v1.1.spec

echo.
echo ============================================================
echo  Building PS-Payload-Injector_v1.1.exe ...
echo ============================================================
python -m PyInstaller ^
    --name "PS-Payload-Injector_v1.1" ^
    --onefile ^
    --windowed ^
    --clean ^
    --noupx ^
    --icon "icon.ico" ^
    --add-data "icon.ico;." ^
    --add-data "data;data" ^
    --exclude-module "PySide6.QtNetwork" ^
    --exclude-module "PySide6.QtQml" ^
    --exclude-module "PySide6.QtQuick" ^
    --exclude-module "PySide6.QtQuickWidgets" ^
    --exclude-module "PySide6.QtWebEngineCore" ^
    --exclude-module "PySide6.QtWebEngineWidgets" ^
    --exclude-module "PySide6.QtWebEngineQuick" ^
    --exclude-module "PySide6.QtMultimedia" ^
    --exclude-module "PySide6.QtMultimediaWidgets" ^
    --exclude-module "PySide6.QtPdf" ^
    --exclude-module "PySide6.QtPdfWidgets" ^
    --exclude-module "PySide6.QtSql" ^
    --exclude-module "PySide6.QtBluetooth" ^
    --exclude-module "PySide6.QtSerialPort" ^
    --exclude-module "PySide6.QtSensors" ^
    --exclude-module "PySide6.QtPositioning" ^
    --exclude-module "PySide6.QtNfc" ^
    --exclude-module "PySide6.QtTest" ^
    --exclude-module "PySide6.QtDesigner" ^
    --exclude-module "PySide6.QtHelp" ^
    --exclude-module "PySide6.QtCharts" ^
    --exclude-module "PySide6.QtDataVisualization" ^
    --exclude-module "PySide6.QtRemoteObjects" ^
    --exclude-module "PySide6.QtScxml" ^
    --exclude-module "PySide6.QtStateMachine" ^
    --exclude-module "PySide6.QtTextToSpeech" ^
    --exclude-module "PySide6.QtVirtualKeyboard" ^
    --exclude-module "PySide6.QtWebChannel" ^
    --exclude-module "PySide6.QtWebSockets" ^
    --exclude-module "PySide6.QtXml" ^
    payload_injector.py

call "%VENV_DIR%\Scripts\deactivate.bat"

echo.
if exist "dist\PS-Payload-Injector_v1.1.exe" (
    echo ============================================================
    echo  BUILD SUCCEEDED
    echo  Output: %PROJECT_DIR%\dist\PS-Payload-Injector_v1.1.exe
    echo  No Python install needed on the target PC - everything is
    echo  embedded. Note: antivirus/SmartScreen may flag or delete
    echo  unsigned PyInstaller exes on first run; add an exclusion
    echo  if that happens.
    echo ============================================================
) else (
    echo ============================================================
    echo  BUILD FAILED - check the output above for errors.
    echo ============================================================
)

pause
endlocal
