@echo off
title DmZ / DmZ FXAP
color 0A

echo.
echo ========================================
echo      DmZ FXAP   /   DmZ FXAP
echo ========================================
echo.

REM Prompt for link
set /p LINK=Enter cfx.re link : 

echo.
echo [*] Launching auto.py with link : %LINK%
echo.

python auto.py %LINK%

echo.
echo ========================================
echo      DmZ FXAP / Dump Finished!
echo   Decrypted resources are in Output
echo ========================================
echo.

pause
