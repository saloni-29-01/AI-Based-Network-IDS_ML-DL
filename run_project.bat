@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AI Network IDS
cd /d "%~dp0"

rem ---- locate Python: prefer the project virtual environment ----
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (
  where py >nul 2>nul && set "PY=py -3.12"
)
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo [FAIL] Python not found. Install Python 3.12 from https://www.python.org/downloads/
  echo        then run:  python -m venv .venv  ^&^&  .venv\Scripts\pip install -r requirements.txt
  pause & exit /b 1
)

rem ---- quick environment checks ----
%PY% -c "import fastapi, sklearn, scapy, psutil" >nul 2>nul
if errorlevel 1 (
  echo [WARN] Required packages are missing.
  set /p INST="Install them now with pip install -r requirements.txt? (Y/N) "
  if /i "!INST!"=="Y" ( %PY% -m pip install -r requirements.txt ) else ( pause & exit /b 1 )
)
if not exist ".env" if exist ".env.example" copy /y ".env.example" ".env" >nul
if not exist "models\registry.json" (
  echo [WARN] No trained models found - running setup.py to prepare data and train models...
  %PY% setup.py || ( pause & exit /b 1 )
)

:menu
cls
echo ========================================
echo            AI NETWORK IDS
echo ========================================
echo   Python : %PY%
if exist "models\registry.json" (echo   Models : trained) else (echo   Models : MISSING)
if exist "data\ids.db" (echo   DB     : data\ids.db) else (echo   DB     : created on first start)
echo ----------------------------------------
echo   1. Start Full Demo
echo   2. Dataset Simulation
echo   3. PCAP Replay
echo   4. Live Monitoring  (needs Npcap + Administrator)
echo   5. Train Models
echo   6. Train GAN
echo   7. Run Tests
echo   8. Open Dashboard
echo   9. Exit
echo ========================================
set "CH="
set /p CH="Select an option [1-9]: "

if "%CH%"=="1" goto demo
if "%CH%"=="2" goto dataset
if "%CH%"=="3" goto pcap
if "%CH%"=="4" goto live
if "%CH%"=="5" goto train
if "%CH%"=="6" goto gan
if "%CH%"=="7" goto tests
if "%CH%"=="8" goto open
if "%CH%"=="9" exit /b 0
goto menu

:startserver
rem Start the server in its own window unless one is already answering.
%PY% scripts\api_call.py health && goto :eof
start "AI Network IDS server" %PY% run.py
echo Waiting for the server to start (models load once at startup)...
for /l %%i in (1,1,90) do (
  %PY% scripts\api_call.py health && goto :eof
  timeout /t 1 /nobreak >nul
)
echo [WARN] Server did not answer within 90 s - check the server window for errors.
goto :eof

:demo
call :startserver
%PY% scripts\api_call.py /api/demo/start
start "" http://127.0.0.1:8000/
pause
goto menu

:dataset
call :startserver
%PY% scripts\api_call.py /api/capture/dataset/start rate=25 speed=1
start "" http://127.0.0.1:8000/
pause
goto menu

:pcap
call :startserver
%PY% scripts\api_call.py /api/replay/start speed=1
start "" http://127.0.0.1:8000/
pause
goto menu

:live
echo Live capture needs Npcap (https://npcap.com, tick "WinPcap API-compatible Mode")
echo and the server started from an Administrator terminal.
call :startserver
%PY% scripts\api_call.py /api/capture/start
start "" http://127.0.0.1:8000/
pause
goto menu

:train
%PY% scripts\train_models.py
pause
goto menu

:gan
%PY% scripts\train_gan.py --epochs 60
pause
goto menu

:tests
%PY% -m pytest
pause
goto menu

:open
start "" http://127.0.0.1:8000/
goto menu
