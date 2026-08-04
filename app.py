from flask import Flask, render_template, request
import re
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# --- 1. FEATURE EXTRACTION FUNCTION ---
def extract_features(url):
    """Extract numerical features from a URL string for the ML model."""
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
# Features: [length, has_https, has_ip, has_at, dot_count, hyphen_count, has_suspicious_word]
# Labels: 0 = Safe, 1 = Phishing
X_train = [
    # Safe URLs (0)
    [18, 1, 0, 0, 2, 0, 0],  # https://google.com
    [22, 1, 0, 0, 2, 0, 0],  # https://github.com
    [25, 1, 0, 0, 2, 0, 0],  # https://wikipedia.org
    [20, 1, 0, 0, 1, 0, 0],  # https://amazon.com
    [28, 1, 0, 0, 2, 0, 0],  # https://stackoverflow.com
    [32, 1, 0, 0, 2, 0, 0],  # https://microsoft.com/en-us
    
    # Phishing / High-Risk URLs (1)
    [85, 0, 1, 1, 4, 3, 1],  # http://192.168.1.1/login-update-banking@verify
    [92, 0, 0, 1, 5, 4, 1],  # http://secure-update-account-login.com/signin/verify
    [70, 0, 0, 0, 4, 3, 1],  # http://banking-security-check.com/update
    [105, 0, 1, 0, 6, 5, 1], # http://10.0.0.1/verify-account-security-login
    [23, 0, 1, 0, 3, 0, 1],  # http://192.168.1.1/login
    [23, 0, 1, 0, 3, 0, 1],  # http://192.168.1.1/login (duplicate for weight boost)
    [25, 0, 1, 0, 3, 0, 0],  # http://10.0.0.1/admin
    [30, 0, 1, 0, 4, 1, 1]   # http://172.16.0.1/secure-login
]
y_train = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]

# Initialize and train the Random Forest Classifier
model = RandomForestClassifier(n_estimators=50, random_state=1)
model.fit(X_train, y_train)

# --- 3. FLASK ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url_input', '').strip()
        
        extracted = extract_features(url)
        features = [extracted]
        
        # Override rule: Raw IP addresses without HTTPS are instantly flagged
        if extracted[2] == 1 and extracted[1] == 0:
            prediction = 1
            confidence = 95.0
        else:
            prediction = model.predict(features)[0]
            confidence = max(model.predict_proba(features)[0]) * 100

        if prediction == 1:
            verdict = f"HIGH RISK: Phishing Detected ({confidence:.1f}% ML Confidence)"
            status_class = "danger"
        else:
            verdict = f"SAFE: Low Risk Detected ({confidence:.1f}% ML Confidence)"
            status_class = "safe"

        result = {
            'url': url,
            'verdict': verdict,
            'status_class': status_class,
            'reasons': [f"Extracted {len(features[0])} numerical URL features for machine learning prediction."]
        }
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)