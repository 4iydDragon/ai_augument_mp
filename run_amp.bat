@echo off
cd /d %~dp0

REM Create virtual environment if it does not exist
if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
call .venv\Scripts\activate

REM Upgrade pip
python -m ensurepip --upgrade
python -m pip install --upgrade pip

REM Install dependencies
pip install -r requirements.txt

REM Run the application

start http://127.0.0.1:5000
python app.py
pause