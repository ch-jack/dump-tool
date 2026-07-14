@echo off
title DmZ Corp / DmZ Corp FXAP
color 0A

echo.
echo ========================================
echo      DmZ Corp FXAP   /   DmZ Corp FXAP
echo ========================================
echo.

REM
set /p LINK=Enter cfx.re link : 

echo.
echo [*] Launching auto.py with link : %LINK%
echo.

python auto.py %LINK%

echo.
echo ========================================
echo      DmZ Corp FXAP / Dump Finished!
echo   Decrypted resources are in Output
echo ========================================
echo.

pause
