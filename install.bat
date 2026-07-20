@echo off
title FiveM Dump Tool 安装与启动
color 0B
chcp 65001 >nul
cls

echo ==================================================
echo        FiveM Dump Tool 自动安装与启动
echo ==================================================
echo.

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] 未找到 Python。
    echo 请安装 Python 3.x，并勾选 Add Python to PATH。
    pause
    exit /b
)

echo [*] 已检测到 Python：
python --version

echo.
echo [*] 正在升级 pip...
python -m pip install --upgrade pip

echo.
echo [*] 正在清理可能冲突的旧 crypto 包...
pip uninstall crypto -y >nul 2>&1
pip uninstall pycrypto -y >nul 2>&1

echo.
echo [*] 正在安装依赖...

IF EXIST requirements.txt (
    echo [*] 使用 requirements.txt 安装依赖。
    pip install -r requirements.txt
) ELSE (
    echo [*] 未找到 requirements.txt，改为手动安装基础依赖。
    pip install psutil requests pycryptodome
)

echo.
echo [*] 正在测试 Crypto 模块...
python -c "from Crypto.Cipher import AES; print('Crypto OK')" 2>nul

IF %ERRORLEVEL% NEQ 0 (
    echo [!] Crypto 模块检测失败。
    echo 请检查当前目录是否存在名为 Crypto 的文件夹，或是否有 crypto.py 冲突。
    pause
    exit /b
)

echo.
echo ========================================
echo        即将启动脚本
echo ========================================
echo.
echo 提示：默认使用 token_choice=1 自动扫描 FiveM token。
echo.

python auto.py

echo.
echo ========================================
echo            已结束
echo ========================================
echo.

pause
