#!/bin/bash

# PhishGuard AI - Start Script
# This script sets up and runs the PhishGuard AI application

echo "==================================="
echo "PhishGuard AI - Setup and Start"
echo "==================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if we're in the correct directory
if [ ! -f "README.md" ] || [ ! -d "backend" ]; then
    echo "Error: Please run this script from the PhishGuard-AI project root directory."
    exit 1
fi

# Navigate to backend directory
cd backend

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Check if model exists
if [ ! -f "phishguard_model.joblib" ]; then
    echo "Model not found. Training model..."
    python train_model.py
else
    echo "Model already trained. Skipping training..."
fi

# Start the server
echo ""
echo "==================================="
echo "Starting PhishGuard AI Server..."
echo "==================================="
echo "Server will be available at: http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo ""

python app.py
