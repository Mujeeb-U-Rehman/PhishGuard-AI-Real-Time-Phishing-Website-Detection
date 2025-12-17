@echo off
REM PhishGuard AI - Windows Start Script

echo ===================================
echo PhishGuard AI - Setup and Start
echo ===================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Navigate to backend directory
cd backend

REM Check if virtual environment exists
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -q -r requirements.txt

REM Check if model exists
if not exist "phishguard_model.joblib" (
    echo Model not found. Training model...
    python train_model.py
) else (
    echo Model already trained. Skipping training...
)

REM Start the server
echo.
echo ===================================
echo Starting PhishGuard AI Server...
echo ===================================
echo Server will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

python app.py
pause
