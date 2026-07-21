@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title FiveM Dump Tool 依赖安装与启动
color 0B
cd /d "%~dp0"
cls

set "DEPENDENCIES_ONLY=0"
set "EXIT_CODE=0"

:parse_arguments
if "%~1"=="" goto arguments_done
if /I "%~1"=="--dependencies-only" (
    set "DEPENDENCIES_ONLY=1"
    shift
    goto parse_arguments
)
echo [!] 不支持的参数：%~1
set "EXIT_CODE=2"
goto finish

:arguments_done
if defined CK_DUMP_PYTHON (
    set "PYTHON_EXE=%CK_DUMP_PYTHON%"
) else (
    set "PYTHON_EXE=python"
)

echo ==================================================
if "%DEPENDENCIES_ONLY%"=="1" (
    echo        FiveM Dump Tool Python 依赖安装
) else (
    echo        FiveM Dump Tool 自动安装与启动
)
echo ==================================================
echo.

"%PYTHON_EXE%" --version >nul 2>&1
if errorlevel 1 (
    echo [!] 未找到或无法运行 Python。
    echo 请先在 CK 免费工具箱中选择 python.exe，或安装 Python 3.x 并添加到 PATH。
    set "EXIT_CODE=1"
    goto finish
)

echo [*] 当前 Python：
"%PYTHON_EXE%" --version
echo [*] 路径：%PYTHON_EXE%

echo.
echo [*] 正在升级 pip...
"%PYTHON_EXE%" -m pip install --upgrade pip
if errorlevel 1 (
    echo [!] pip 升级失败，将继续尝试安装依赖。
)

echo.
echo [*] 正在清理可能冲突的旧 crypto 包...
"%PYTHON_EXE%" -m pip uninstall crypto -y >nul 2>&1
"%PYTHON_EXE%" -m pip uninstall pycrypto -y >nul 2>&1

echo.
echo [*] 正在安装依赖...
if exist "requirements.txt" (
    echo [*] 使用 requirements.txt 安装依赖。
    "%PYTHON_EXE%" -m pip install -r "requirements.txt"
) else (
    echo [*] 未找到 requirements.txt，改为安装基础依赖。
    "%PYTHON_EXE%" -m pip install psutil requests pycryptodome
)
if errorlevel 1 (
    echo [!] Python 依赖安装失败，请检查网络、权限和上方错误信息。
    set "EXIT_CODE=1"
    goto finish
)

echo.
echo [*] 正在检测 psutil、requests 和 Crypto 解密模块...
"%PYTHON_EXE%" -c "import psutil, requests; from Crypto.Cipher import AES, ChaCha20; print('Python 依赖检测通过')"
if errorlevel 1 (
    echo [!] Python 依赖检测失败。
    echo 请检查当前目录是否存在 Crypto 文件夹或 crypto.py，确认没有同名文件冲突。
    set "EXIT_CODE=1"
    goto finish
)

if "%DEPENDENCIES_ONLY%"=="1" (
    echo.
    echo [√] Dump 所需 Python 依赖已经安装完成。
    goto finish
)

echo.
echo ========================================
echo        即将启动 Dump Tool
echo ========================================
echo.
echo 提示：默认使用 token_choice=1 自动扫描 FiveM token。
echo.

"%PYTHON_EXE%" "auto.py"
set "EXIT_CODE=%ERRORLEVEL%"

:finish
echo.
echo ========================================
if "%EXIT_CODE%"=="0" (
    echo            操作已完成
) else (
    echo            操作失败
)
echo ========================================
echo.

if /I not "%CK_DUMP_NO_PAUSE%"=="1" pause
exit /b %EXIT_CODE%
