/**
 * PhishGuard AI - Frontend JavaScript
 * Handles form submission and API communication
 */

// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// DOM Elements
const urlForm = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultMessage = document.getElementById('resultMessage');
const confidence = document.getElementById('confidence');
const riskLevel = document.getElementById('riskLevel');
const checkAnotherBtn = document.getElementById('checkAnother');

// Event Listeners
urlForm.addEventListener('submit', handleSubmit);
checkAnotherBtn.addEventListener('click', resetForm);

/**
 * Handle form submission
 */
async function handleSubmit(e) {
    e.preventDefault();
    
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    
    // Validate URL format
    if (!isValidURL(url)) {
        showError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }
    
    // Show loading state
    showLoading();
    
    try {
        // Call API
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error('Failed to analyze URL');
        }
        
        const data = await response.json();
        
        // Show result
        showResult(data);
        
    } catch (error) {
        console.error('Error:', error);
        showError('An error occurred while analyzing the URL. Please try again.');
        hideLoading();
    }
}

/**
 * Validate URL format
 */
function isValidURL(string) {
    try {
        // Check if URL has a protocol
        if (!string.startsWith('http://') && !string.startsWith('https://')) {
            string = 'https://' + string;
            urlInput.value = string;
        }
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * Show loading state
 */
function showLoading() {
    urlForm.classList.add('hidden');
    result.classList.add('hidden');
    loading.classList.remove('hidden');
}

/**
 * Hide loading state
 */
function hideLoading() {
    loading.classList.add('hidden');
}

/**
 * Show result
 */
function showResult(data) {
    hideLoading();
    
    // Update result content
    const isPhishing = data.prediction === 'phishing';
    const confidencePercent = (data.confidence * 100).toFixed(1);
    
    // Update result class
    result.className = 'result';
    result.classList.add(isPhishing ? 'danger' : 'safe');
    
    // Update result title and icon
    if (isPhishing) {
        resultTitle.textContent = '⚠️ Warning: Phishing Detected!';
        resultIcon.innerHTML = `
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
        `;
    } else {
        resultTitle.textContent = '✓ Safe Website';
        resultIcon.innerHTML = `
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <path d="M22 4L12 14.01l-3-3"></path>
        `;
    }
    
    // Update result message
    resultMessage.textContent = data.message;
    
    // Update confidence
    confidence.textContent = `${confidencePercent}%`;
    
    // Update risk level
    riskLevel.textContent = data.risk_level.charAt(0).toUpperCase() + data.risk_level.slice(1);
    riskLevel.className = `detail-value risk-badge ${data.risk_level}`;
    
    // Show result
    result.classList.remove('hidden');
}

/**
 * Show error message
 */
function showError(message) {
    alert(message);
}

/**
 * Reset form
 */
function resetForm() {
    urlForm.classList.remove('hidden');
    result.classList.add('hidden');
    urlInput.value = '';
    urlInput.focus();
}

/**
 * Smooth scrolling for navigation links
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

/**
 * Check API health on page load
 */
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        const data = await response.json();
        
        if (!data.model_loaded) {
            console.warn('Warning: ML model is not loaded. Please train the model first.');
        }
    } catch (error) {
        console.error('Warning: Could not connect to backend API:', error);
        console.log('Make sure the backend server is running on http://localhost:5000');
    }
}

// Check API health on page load
checkAPIHealth();
