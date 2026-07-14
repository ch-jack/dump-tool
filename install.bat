@echo off
title AUTO SETUP + RUN
color 0B
cls

echo ==================================================
echo        AUTO SETUP + LAUNCH BY DmZ
echo ==================================================
echo.

REM 
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] Python not found.
    echo Please install Python 3.x and ADD IT TO PATH.
    pause
    exit /b
)

echo [*] Python detected!
python --version

echo.
echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo.
echo [*] Cleaning bad crypto packages...
pip uninstall crypto -y >nul 2>&1
pip uninstall pycrypto -y >nul 2>&1

echo.
echo [*] Installing dependencies...

IF EXIST requirements.txt (
    echo [*] Using requirements.txt
    pip install -r requirements.txt
) ELSE (
    echo [*] No requirements.txt found, installing manually...
    pip install psutil requests pycryptodome
)

echo.
echo [*] Testing Crypto module...
python -c "from Crypto.Cipher import AES; print('Crypto OK')" 2>nul

IF %ERRORLEVEL% NEQ 0 (
    echo [!] Crypto error detected!
    echo Check for a folder named "Crypto" or file "crypto.py"
    pause
    exit /b
)

echo.
echo ========================================
echo        LAUNCHING SCRIPT
echo ========================================
echo.

python auto.py

echo.
echo ========================================
echo            FINISHED
echo ========================================
echo.

pause