@echo off
title DmZ Corp / FiveM 服务器 Dump
color 0A
chcp 65001 >nul

echo.
echo ========================================
echo        FiveM 服务器 Dump / FXAP 解密
echo ========================================
echo.
echo 功能范围：包含服务器 Dump、FXAP 解密；不含模型修复。
echo 默认 token 方式：1 - 自动扫描 FiveM 进程。
echo.

set /p LINK=请输入 cfx.re 链接或 IP:端口: 

echo.
echo [*] 正在启动 auto.py，目标：%LINK%
echo.

python auto.py "%LINK%" --token-choice 1

echo.
echo ========================================
echo        任务结束
echo   解密输出目录：Output
echo   报告文件：Output\_server_dump_report.md
echo ========================================
echo.

pause
