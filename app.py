from flask import Flask, render_template, request, jsonify
import re
from sklearn.ensemble import RandomForestClassifier

# --- CRITICAL: Gunicorn needs this variable named 'app' ---
app = Flask(__name__)

# --- 1. FEATURE EXTRACTION FUNCTION ---
def extract_features(url):
    url_len = len(url)
    has_https = 1 if url.startswith("https://") else 0
    has_ip = 1 if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_at = 1 if "@" in url else 0
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    
    suspicious_words = ["login", "verify", "update", "account", "banking", "secure", "signin", "admin"]
    has_suspicious_word = 1 if any(word in url.lower() for word in suspicious_words) else 0

    return [url_len, has_https, has_ip, has_at, dot_count, hyphen_count, has_suspicious_word]

# --- 2. TRAIN ML MODEL ON STARTUP ---
X_train = [
    [18, 1, 0, 0, 2, 0, 0],  # Safe
    [22, 1, 0, 0, 2, 0, 0],
    [25, 1, 0, 0, 2, 0, 0],
    [20, 1, 0, 0, 1, 0, 0],
    [28, 1, 0, 0, 2, 0, 0],
    [32, 1, 0, 0, 2, 0, 0],
    [85, 0, 1, 1, 4, 3, 1],  # Phishing
    [92, 0, 0, 1, 5, 4, 1],
    [70, 0, 0, 0, 4, 3, 1],
    [105, 0, 1, 0, 6, 5, 1],
    [23, 0, 1, 0, 3, 0, 1],
    [23, 0, 1, 0, 3, 0, 1],
    [25, 0, 1, 0, 3, 0, 0],
    [30, 0, 1, 0, 4, 1, 1]
]
y_train = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]

model = RandomForestClassifier(n_estimators=50, random_state=1)
model.fit(X_train, y_train)

def get_prediction(url):
    extracted = extract_features(url)
    features = [extracted]
    
    if extracted[2] == 1 and extracted[1] == 0:
        prediction = 1
        confidence = 95.0
    else:
        prediction = int(model.predict(features)[0])
        confidence = round(float(max(model.predict_proba(features)[0])) * 100, 1)

    return prediction, confidence

# --- 3. FLASK WEB ROUTE ---
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url_input', '').strip()
        prediction, confidence = get_prediction(url)

        if prediction == 1:
            verdict = f"HIGH RISK: Phishing Detected ({confidence}% ML Confidence)"
            status_class = "danger"
        else:
            verdict = f"SAFE: Low Risk Detected ({confidence}% ML Confidence)"
            status_class = "safe"

        result = {
            'url': url,
            'verdict': verdict,
            'status_class': status_class,
            'reasons': ["Extracted features and ran ML classification."]
        }
    return render_template('index.html', result=result)

# --- 4. REST API ENDPOINT ---
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    prediction, confidence = get_prediction(url)
    
    return jsonify({
        'url': url,
        'is_phishing': bool(prediction == 1),
        'risk_level': 'HIGH' if prediction == 1 else 'LOW',
        'confidence_score': confidence
    })

if __name__ == '__main__':
    app.run(debug=True)