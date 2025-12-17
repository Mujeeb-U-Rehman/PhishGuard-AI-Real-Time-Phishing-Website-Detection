# PhishGuard AI - Quick Start Guide

## 🚀 Getting Started in 3 Steps

### Step 1: Install Python
Make sure you have Python 3.8 or higher installed:
```bash
python --version
```

### Step 2: Run the Application

#### On Windows:
Double-click `start.bat` or run in terminal:
```batch
start.bat
```

#### On macOS/Linux:
Make the script executable and run:
```bash
chmod +x start.sh
./start.sh
```

Or run manually:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python train_model.py  # First time only
python app.py
```

### Step 3: Open Your Browser
Navigate to:
```
http://localhost:5000
```

## 🎯 Using the Application

1. **Enter a URL** - Type or paste any website URL
2. **Click "Check URL"** - The AI will analyze it
3. **View Results** - See if it's safe or phishing with confidence score

## 📝 Examples to Try

**Safe URLs:**
- https://www.google.com
- https://github.com
- https://www.amazon.com

**Suspicious Patterns:**
- URLs with IP addresses
- Very long URLs
- URLs with @ symbols
- Non-HTTPS URLs with login forms

## 🔧 Troubleshooting

### Model not found error?
Run the training script:
```bash
cd backend
python train_model.py
```

### Port already in use?
Change the port in backend/app.py or set environment variable:
```bash
export PORT=8000  # Linux/Mac
set PORT=8000     # Windows
```

### Dependencies installation fails?
Update pip first:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## 🌐 API Usage

### Check URL via API
```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Health Check
```bash
curl http://localhost:5000/api/health
```

## 📚 More Information

For detailed documentation, see [README.md](README.md)

---

**Need Help?** Open an issue on GitHub
