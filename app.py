from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import re
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)
CORS(app)  # Enables Chrome Extension to make API requests to this server

# --- 1. FEATURE EXTRACTION FUNCTION ---
def extract_features(url):
    url_len = len(url)
    has_https = 1 if url.startswith("https://") else 0
    has_ip = 1 if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_at = 1 if "@" in url else 0
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    
    suspicious_words = ["login", "verify", "update", "account", "banking", "secure", "signin"]
    has_suspicious_word = 1 if any(word in url.lower() for word in suspicious_words) else 0

    return [url_len, has_https, has_ip, has_at, dot_count, hyphen_count, has_suspicious_word]

# --- 2. TRAIN ML MODEL ON STARTUP ---
X_train = [
    [18, 1, 0, 0, 2, 0, 0],
    [22, 1, 0, 0, 2, 0, 0],
    [25, 1, 0, 0, 2, 0, 0],
    [85, 0, 1, 1, 4, 3, 1],
    [92, 0, 0, 1, 5, 4, 1],
    [70, 0, 0, 0, 4, 3, 1],
    [20, 1, 0, 0, 1, 0, 0],
    [105, 0, 1, 0, 6, 5, 1]
]
y_train = [0, 0, 0, 1, 1, 1, 0, 1]

model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X_train, y_train)

# --- 3. WEB PAGE ROUTE ---
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url_input', '')
        features = [extract_features(url)]
        prediction = model.predict(features)[0]
        confidence = max(model.predict_proba(features)[0]) * 100

        verdict = f"HIGH RISK: Phishing ({confidence:.1f}%)" if prediction == 1 else f"SAFE ({confidence:.1f}%)"
        status_class = "danger" if prediction == 1 else "safe"

        result = {
            'url': url,
            'verdict': verdict,
            'status_class': status_class,
            'reasons': [f"Evaluated using ML Random Forest classifier."]
        }
    return render_template('index.html', result=result)

# --- 4. API ROUTE FOR BROWSER EXTENSION ---
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    url = data.get('url', '') if data else ''

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = [extract_features(url)]
    prediction = model.predict(features)[0]
    confidence = max(model.predict_proba(features)[0]) * 100

    return jsonify({
        'url': url,
        'is_phishing': bool(prediction == 1),
        'confidence': round(confidence, 1),
        'verdict': 'Phishing Detected' if prediction == 1 else 'Safe'
    })

if __name__ == '__main__':
    app.run(debug=True)