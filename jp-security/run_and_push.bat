@echo off
REM JP Security Monitor - 実行バッチ（pull → 実行 → push）
echo [%DATE% %TIME%] 開始

cd /d "%~dp0.."
git pull --rebase origin main
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] pull --rebase 失敗
    git rebase --abort 2>nul
    exit /b 1
)

cd /d "%~dp0"
"C:\Users\otomo\AppData\Local\Python\pythoncore-3.14-64\python.exe" jp_security_monitor.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python失敗: %ERRORLEVEL%
    exit /b 1
)

cd /d "%~dp0.."
git add jp-security/index.html jp-security/jp_security_seen.json
git diff --cached --quiet || git commit -m "auto update jp-security: %DATE% %TIME%"

git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] push失敗 - 再試行します
    git pull --rebase origin main
    git push origin main
)

echo [%DATE% %TIME%] 完了
