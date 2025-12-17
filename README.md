# PhishGuard AI - Real-Time Phishing Website Detection

A professional web application that uses machine learning to detect phishing websites in real-time. Built with Flask backend and modern frontend technologies.

## 🚀 Features

- **Real-time Detection**: Instantly analyze URLs for phishing threats
- **High Accuracy**: Random Forest ML model trained on 30+ URL features
- **Professional UI**: Modern, responsive design with intuitive user experience
- **REST API**: Easy-to-use API endpoints for integration
- **Detailed Results**: Get confidence scores and risk levels for each prediction

## 🏗️ Project Structure

```
PhishGuard-AI/
├── backend/
│   ├── app.py                  # Flask API server
│   ├── train_model.py          # Model training script
│   ├── feature_extraction.py   # URL feature extraction
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── index.html             # Main HTML page
│   ├── styles.css             # CSS styling
│   └── script.js              # JavaScript functionality
├── DataSet.xlsx               # Training dataset
├── Source Code.ipynb          # Original Jupyter notebook
└── README.md                  # This file
```

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Modern web browser (Chrome, Firefox, Safari, Edge)

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Mujeeb-U-Rehman/PhishGuard-AI-Real-Time-Phishing-Website-Detection.git
cd PhishGuard-AI-Real-Time-Phishing-Website-Detection
```

### 2. Set Up Backend

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Train the Model

```bash
# Make sure you're in the backend directory
python train_model.py
```

This will:
- Load the dataset from `../DataSet.xlsx`
- Train a Random Forest classifier
- Save the model as `phishguard_model.joblib`
- Save feature names as `feature_names.joblib`

### 4. Start the Backend Server

```bash
python app.py
```

The server will start on `http://localhost:5000`

### 5. Open the Frontend

Open your web browser and navigate to:
```
http://localhost:5000
```

## 🎯 Usage

### Web Interface

1. Open the application in your browser
2. Enter a URL in the input field (e.g., `https://example.com`)
3. Click "Check URL"
4. View the results:
   - **Prediction**: Legitimate or Phishing
   - **Confidence**: Probability score (0-100%)
   - **Risk Level**: High or Low

### API Usage

#### Health Check

```bash
curl http://localhost:5000/api/health
```

#### Predict URL

```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## 🧠 How It Works

### Feature Extraction

The system analyzes 30+ features from each URL including:
- URL-based features (length, special characters, IP address presence)
- Domain features (subdomain count, SSL status, domain age)
- Security features (HTTPS usage, port numbers)

### Machine Learning Model

- **Algorithm**: Random Forest Classifier
- **Training Data**: Phishing and legitimate URLs from DataSet.xlsx
- **Features**: 30 engineered features
- **Performance**: High accuracy, precision, and recall

## 🚀 Deployment

### Using Gunicorn (Production)

```bash
cd backend
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 🛡️ Security Features

- URL validation and sanitization
- CORS protection
- Error handling and input validation
- No storage of user-submitted URLs

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Stay Safe Online! 🛡️**