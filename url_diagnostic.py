import pickle
import pandas as pd
import math

# Load the URL brain directly
with open('aegis_url_model_v2.pkl', 'rb') as f:
    url_model = pickle.load(f)

def extract_features(url):
    length = len(url)
    digits = sum(c.isdigit() for c in url)
    digit_ratio = digits / length if length > 0 else 0
    prob = [float(url.count(c)) / length for c in dict.fromkeys(list(url))]
    entropy = - sum(p * math.log(p, 2) for p in prob) if length > 0 else 0
    dots = url.count('.')
    hyphens = url.count('-')
    ats = url.count('@')
    is_https = 1 if url.startswith('https') else 0
    suspicious_tld = 1 if any(tld in url.lower() for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.site', '.info']) else 0
    phishing_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'free']
    keyword_count = sum(url.lower().count(kw) for kw in phishing_keywords)
    
    features = [length, digit_ratio, entropy, dots, hyphens, ats, is_https, suspicious_tld, keyword_count]
    feature_names = ['url_length', 'digit_ratio', 'entropy', 'count_dots', 'count_hyphens', 'count_at', 'is_https', 'suspicious_tld', 'keyword_count']
    return pd.DataFrame([features], columns=feature_names)

print("--- AEGISQ URL DIAGNOSTIC ---")
print(f"Model Classes (Internal Labels): {url_model.classes_}")

test_urls = [
    "https://www.google.com",  # Should be 100% safe
    "https://en.wikipedia.org/wiki/Computer_security", # The tricky one
    "http://secure-login-bank-update.xyz" # Should be 100% malicious
]

for u in test_urls:
    df = extract_features(u)
    # Get the raw probability array [Probability of Class 0, Probability of Class 1]
    proba = url_model.predict_proba(df)[0]
    print(f"\nURL: {u}")
    print(f"Raw Probabilities: Class 0 = {proba[0]:.4f}, Class 1 = {proba[1]:.4f}")