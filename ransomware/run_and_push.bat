@echo off
cd /d "%~dp0"
"C:\Users\otomo\AppData\Local\Python\pythoncore-3.14-64\python.exe" jp_ransomware_monitor.py
git -C "%~dp0.." add ransomware/index.html ransomware/jp_ransomware_report.csv ransomware/jp_ransomware_seen.json
git -C "%~dp0.." diff --cached --quiet || git -C "%~dp0.." commit -m "auto update: %DATE% %TIME%"
git -C "%~dp0.." pull --rebase origin main
git -C "%~dp0.." push origin main
