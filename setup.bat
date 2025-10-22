@echo off
REM HEC-Yeah Setup Script for Windows
REM This script automates the initial setup process

setlocal enabledelayedexpansion

echo ============================================================
echo HEC-Yeah Setup
echo ============================================================
echo.

REM Check if Python 3 is installed
echo Checking for Python 3...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3 from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo [32m✓ Found !PYTHON_VERSION![0m
echo.

REM Create virtual environment
echo Creating Python virtual environment...
if exist "venv" (
    echo [33mVirtual environment already exists, skipping creation[0m
) else (
    python -m venv venv
    echo [32m✓ Virtual environment created[0m
)
echo.

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
echo [32m✓ Virtual environment activated[0m
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo [32m✓ pip upgraded[0m
echo.

REM Install requirements
echo Installing dependencies from requirements.txt...
pip install -r requirements.txt
echo [32m✓ Dependencies installed[0m
echo.

REM Copy .env.example to .env
echo Setting up configuration file...
if exist ".env" (
    echo [33mWarning: .env file already exists[0m
    set /p "OVERWRITE=Do you want to overwrite it? (y/N): "
    if /i "!OVERWRITE!"=="y" (
        copy /y .env.example .env >nul
        echo [32m✓ .env file created (overwritten)[0m
    ) else (
        echo [33mKeeping existing .env file[0m
    )
) else (
    copy .env.example .env >nul
    echo [32m✓ .env file created from .env.example[0m
)
echo.

REM Setup complete
echo ============================================================
echo [32mSetup Complete![0m
echo ============================================================
echo.

echo [33mNext Steps:[0m
echo 1. Edit the .env file with your configuration:
echo    notepad .env
echo.
echo 2. Set TEST_TARGET in .env:
echo    - cribl - Test Cribl only
echo    - splunk - Test Splunk only (default)
echo    - both - Test both Cribl and Splunk
echo.
echo 3. Configure required values based on your testing target:
echo.
echo    For Cribl testing (TEST_TARGET=cribl or both):
echo    - CRIBL_HTTP_URL
echo    - CRIBL_API_URL
echo    - CRIBL_CLIENT_ID
echo    - CRIBL_CLIENT_SECRET
echo    [33mGenerate API credentials in Cribl: Settings → API Credentials[0m
echo.
echo    For Splunk testing (TEST_TARGET=splunk or both):
echo    - SPLUNK_HEC_URL
echo    - SPLUNK_HEC_TOKEN
echo    - SPLUNK_HTTP_URL
echo    - SPLUNK_USERNAME
echo    - SPLUNK_TOKEN or SPLUNK_PASSWORD (token preferred)
echo    [33mNote: If using SAML/SSO, you MUST use SPLUNK_TOKEN[0m
echo.
echo 4. When ready, activate the virtual environment and run HEC-Yeah:
echo    [32mvenv\Scripts\activate[0m
echo    [32mpython hec_yeah.py[0m
echo.

echo For help, run: [34mpython hec_yeah.py --help[0m
echo.

pause
