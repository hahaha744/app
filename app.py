from flask import Flask, render_template, request
import re

app = Flask(__name__)

def analyze_url(url):
    reasons = []
    score = 0  # Higher score = higher suspicion

    # 1. Check for missing HTTPS
    if not url.startswith("https://"):
        score += 2
        reasons.append("Does not use secure HTTPS encryption.")

    # 2. Check if IP address is used instead of a domain name
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 3
        reasons.append("Uses an IP address instead of a recognized domain name.")

    # 3. Check for suspicious symbols like '@' (used to disguise actual destinations)
    if "@" in url:
        score += 3
        reasons.append("Contains an '@' symbol, which can hide the real destination domain.")

    # 4. Check for URL length (phishing links are often unnaturally long)
    if len(url) > 75:
        score += 2
        reasons.append("URL is unusually long (over 75 characters).")

    # 5. Check for common phishing keywords in the URL
    suspicious_keywords = ["login", "verify", "update", "account", "banking", "secure", "signin"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score += 1
        reasons.append("Contains urgent security keywords commonly seen in phishing attacks.")

    # Determine verdict based on overall risk score
    if score >= 4:
        verdict = "HIGH RISK: Likely Phishing"
        status_class = "danger"
    elif score >= 2:
        verdict = "MODERATE RISK: Proceed with Caution"
        status_class = "warning"
    else:
        verdict = "SAFE: Low Phishing Risk Detected"
        status_class = "safe"

    return verdict, status_class, reasons

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        url = request.form.get('url_input', '')
        verdict, status_class, reasons = analyze_url(url)
        result = {
            'url': url,
            'verdict': verdict,
            'status_class': status_class,
            'reasons': reasons
        }
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)