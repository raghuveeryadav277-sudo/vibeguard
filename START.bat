@echo off
title VibeGuard
cd /d "%~dp0"
echo.
echo  Starting VibeGuard... your browser will open automatically.
echo  Keep this black window OPEN while you use the app.
echo  To stop VibeGuard, close this window.
echo.
py -3 run.py 2>nul || python run.py 2>nul || python3 run.py
echo.
echo  VibeGuard has stopped. Press any key to close this window.
pause >nul
