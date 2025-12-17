"""
PhishGuard AI - Flask Backend API
Provides REST API for phishing URL detection
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import pandas as pd
import os
from feature_extraction import extract_features

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)  # Enable CORS for all routes

# Load the trained model
MODEL_PATH = 'phishguard_model.joblib'
FEATURES_PATH = 'feature_names.joblib'

try:
    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print(f"Model loaded successfully with {len(feature_names)} features")
except FileNotFoundError:
    model = None
    feature_names = None
    print("Model not found. Please train the model first using train_model.py")

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('../frontend', 'index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None
    })

@app.route('/api/predict', methods=['POST'])
def predict():
    """
    Predict if a URL is phishing or legitimate
    
    Request body:
    {
        "url": "https://example.com"
    }
    
    Response:
    {
        "url": "https://example.com",
        "prediction": "legitimate" or "phishing",
        "confidence": 0.95,
        "result": 1 or -1
    }
    """
    try:
        # Check if model is loaded
        if model is None:
            return jsonify({
                'error': 'Model not loaded. Please train the model first.'
            }), 500
        
        # Get URL from request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required in request body'
            }), 400
        
        url = data['url']
        
        # Validate URL
        if not url or not url.strip():
            return jsonify({
                'error': 'URL cannot be empty'
            }), 400
        
        # Extract features
        features = extract_features(url)
        
        # Create DataFrame with features in correct order
        feature_df = pd.DataFrame([features])
        
        # Ensure all required features are present
        for feature_name in feature_names:
            if feature_name not in feature_df.columns:
                feature_df[feature_name] = 1  # Default value
        
        # Select features in the same order as training
        feature_df = feature_df[feature_names]
        
        # Make prediction
        prediction = model.predict(feature_df)[0]
        prediction_proba = model.predict_proba(feature_df)[0]
        
        # Get confidence (probability of predicted class)
        if prediction == -1:  # Phishing
            confidence = prediction_proba[0]  # Probability of class -1
            result_text = "phishing"
            risk_level = "high"
        else:  # Legitimate
            confidence = prediction_proba[1]  # Probability of class 1
            result_text = "legitimate"
            risk_level = "low"
        
        return jsonify({
            'url': url,
            'prediction': result_text,
            'confidence': float(confidence),
            'result': int(prediction),
            'risk_level': risk_level,
            'message': f'This URL is predicted to be {result_text} with {confidence*100:.1f}% confidence.'
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Error processing request: {str(e)}'
        }), 500

@app.route('/api/model-info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    if model is None:
        return jsonify({
            'error': 'Model not loaded'
        }), 500
    
    return jsonify({
        'model_type': 'Random Forest Classifier',
        'num_features': len(feature_names),
        'features': feature_names,
        'description': 'PhishGuard AI uses a Random Forest machine learning model trained on 30 URL features to detect phishing websites.'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
