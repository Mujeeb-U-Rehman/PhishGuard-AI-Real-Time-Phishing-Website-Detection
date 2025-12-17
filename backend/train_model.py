"""
PhishGuard AI - Model Training Script
Trains a Random Forest model for phishing URL detection
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
from time import perf_counter
import joblib
import os

def train_model():
    """Train the Random Forest model and save it"""
    
    print("Loading dataset...")
    # Load the dataset
    df = pd.read_excel('../DataSet.xlsx')
    
    # Drop unnamed column if exists
    if 'Unnamed: 0' in df.columns:
        df = df.drop('Unnamed: 0', axis=1)
    
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Separate features and target
    X = df.drop('result', axis=1)
    y = df['result']
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print("\nTraining Random Forest model...")
    # Train Random Forest model
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )
    
    start_time = perf_counter()
    rf_model.fit(X_train, y_train)
    end_time = perf_counter()
    training_time = end_time - start_time
    
    # Make predictions
    y_pred = rf_model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    f1score = f1_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n=== Model Performance ===")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"F1-Score: {f1score:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"Training Time: {training_time:.2f} seconds")
    print(f"\nConfusion Matrix:")
    print(cm)
    
    # Save the model
    model_path = 'phishguard_model.joblib'
    joblib.dump(rf_model, model_path)
    print(f"\nModel saved to {model_path}")
    
    # Save feature names for later use
    feature_names = X.columns.tolist()
    joblib.dump(feature_names, 'feature_names.joblib')
    print(f"Feature names saved to feature_names.joblib")
    
    return rf_model, feature_names

if __name__ == "__main__":
    train_model()
