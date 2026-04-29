@echo off
REM JP Ransomware Monitor - 実行バッチ
REM pull → スクリプト実行 → push の順で競合を防ぐ
echo [%DATE% %TIME%] 開始

cd /d "%~dp0.."
git pull --rebase origin main
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] pull --rebase 失敗
    git rebase --abort 2>nul
    exit /b 1
)

cd /d "%~dp0"
"C:\Users\otomo\AppData\Local\Python\pythoncore-3.14-64\python.exe" jp_ransomware_monitor.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python失敗: %ERRORLEVEL%
    exit /b 1
)

cd /d "%~dp0.."
git add ransomware/index.html ransomware/jp_ransomware_report.csv ransomware/jp_ransomware_seen.json
git diff --cached --quiet || git commit -m "auto update: %DATE% %TIME%"

git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] push失敗 - 再試行します
    git pull --rebase origin main
    git push origin main
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] push再試行も失敗
        exit /b 1
    )
)

echo [%DATE% %TIME%] 完了
