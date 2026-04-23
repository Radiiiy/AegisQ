from fastapi import FastAPI, UploadFile, File, HTTPException
import tensorflow as tf
import pickle
import numpy as np
import cv2
import pandas as pd
import tldextract
from collections import Counter
from scipy.stats import entropy as scipy_entropy
import xgboost as xgb
import shap

app = FastAPI()

# --- 1. LOAD THE BRAINS ---
print("AegisQ: Loading Dual-Layer AI Models...")

vision_model = tf.keras.models.load_model('aegis_cv_model.h5')

with open('aegis_url_model_v2.pkl', 'rb') as f:
    url_model = pickle.load(f)

with open('whitelist.txt', 'r') as f:
    trusted_domains = {
        line.strip().lower()
        for line in f
        if line.strip() and not line.startswith('#')
    }
print(f"AegisQ: Loaded {len(trusted_domains)} trusted domains from whitelist.")

shap_explainer = shap.TreeExplainer(url_model)
print("AegisQ: SHAP explainer ready.")

# --- 2. URL FEATURE EXTRACTION MATH ---
def _calculate_entropy(url):
    prob = [n / len(url) for n in Counter(url).values()]
    return scipy_entropy(prob, base=2)

def extract_url_features(url):
    """Translates a URL string into the exact 9 numbers the XGBoost brain expects."""
    url = str(url)
    features = {}

    features['url_length'] = len(url)
    features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url)
    features['entropy'] = _calculate_entropy(url)
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['is_https'] = 1 if url.startswith('https') else 0

    ext = tldextract.extract(url)
    suspicious_tlds = ['zip', 'top', 'xyz', 'work', 'bid', 'click']
    features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0

    keywords = ['login', 'verify', 'secure', 'update', 'banking', 'lanka', 'gift', 'reward']
    features['keyword_count'] = sum(1 for word in keywords if word in url.lower())

    return pd.DataFrame([features])

def is_whitelisted(url):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    return domain in trusted_domains

# --- 3. SHAP EXPLANATION ---
_FEATURE_REASONS = {
    'url_length':    "The URL is unusually long, a common tactic to hide a malicious destination.",
    'digit_ratio':   "The URL contains a high proportion of digits, typical of auto-generated phishing links.",
    'entropy':       "The URL has high character randomness, suggesting an obfuscated or machine-generated address.",
    'count_dots':    "The URL contains an excessive number of dots, often used to fake legitimate subdomains.",
    'count_hyphens': "The URL contains many hyphens, commonly used to mimic trusted brand names.",
    'count_at':      "The URL contains an @ symbol, which can be used to disguise the true destination.",
    'is_https':      "The URL does not use HTTPS, meaning the connection is unencrypted and unverified.",
    'suspicious_tld':"The URL uses a suspicious top-level domain commonly associated with phishing sites.",
    'keyword_count': "The URL contains phishing keywords such as 'login', 'verify', or 'secure'.",
}

def get_shap_explanation(url_features_df):
    shap_values = shap_explainer.shap_values(url_features_df)
    # For binary XGBoost, shap_values may be a list [neg_class, pos_class] or a single array
    if isinstance(shap_values, list):
        values = shap_values[1][0]
    else:
        values = shap_values[0]

    feature_names = url_features_df.columns.tolist()
    feature_vals = url_features_df.iloc[0].tolist()

    # Rank features by absolute SHAP impact, keep only positive contributors to malicious score
    ranked = sorted(
        zip(feature_names, values, feature_vals),
        key=lambda x: x[1],
        reverse=True
    )

    risk_factors = []
    for name, impact, value in ranked:
        if impact <= 0:
            continue
        if impact > 0.15:
            level = "HIGH"
        elif impact > 0.05:
            level = "MEDIUM"
        else:
            level = "LOW"
        risk_factors.append({
            "feature": name,
            "value": round(float(value), 4),
            "impact": round(float(impact), 4),
            "impact_level": level,
            "reason": _FEATURE_REASONS.get(name, "This feature contributed to the malicious classification."),
        })

    if not risk_factors:
        summary = "The URL was flagged as malicious based on a combination of subtle risk signals."
    else:
        top = risk_factors[0]
        summary = (
            f"The primary risk signal was '{top['feature']}' ({top['impact_level']} impact): "
            f"{top['reason']}"
        )

    return {"risk_factors": risk_factors, "summary": summary}

@app.get("/")
def home():
    return {"status": "AegisQ Backend is LIVE", "message": "Ready for dual-layer scan requests."}

# --- 3. THE MASTER SCAN ENDPOINT ---
@app.post("/scan")
async def scan_qr(file: UploadFile = File(...)):
    contents = await file.read()
    nparr = np.frombuffer(contents, np.uint8)
    img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img_bgr is None:
        raise HTTPException(status_code=400, detail="Could not decode image. Please upload a valid image file.")
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    
    # ==========================================
    # LAYER 1: VISION (Physical Tampering)
    # ==========================================
    img_resized = cv2.resize(img_rgb, (224, 224))
    img_tensor = img_resized.astype('float32') / 255.0
    
    img_batch = np.expand_dims(img_tensor, axis=0)
    v_pred = vision_model.predict(img_batch)
    
    v_confidence = float(v_pred[0][0])
    vision_verdict = "DANGEROUS" if v_confidence > 0.5 else "SAFE"
    
    # ==========================================
    # LAYER 2: URL (Digital Phishing)
    # ==========================================
    url_verdict = "UNKNOWN"
    url_confidence = 0.0
    extracted_url = "No URL Found"
    url_explanation = None
    
    # Use OpenCV's built-in QR scanner to read the text
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img_bgr)
    
    if data:
        extracted_url = data
        if is_whitelisted(extracted_url):
            url_verdict = "SAFE"
            url_confidence = 0.0
        else:
            try:
                url_features_df = extract_url_features(extracted_url)
                u_pred = url_model.predict_proba(url_features_df)[0][1]
                url_confidence = float(u_pred)
                url_verdict = "MALICIOUS" if url_confidence > 0.5 else "SAFE"
                if url_verdict == "MALICIOUS":
                    url_explanation = get_shap_explanation(url_features_df)
            except Exception as e:
                url_verdict = "ERROR"
                url_confidence = 0.0
                extracted_url = f"Feature extraction failed: {e}"
    
    # ==========================================
    # FINAL AEGISQ VERDICT
    # ==========================================
    # If EITHER layer detects a threat, the entire QR code is blocked.
    if vision_verdict == "DANGEROUS" or url_verdict == "MALICIOUS":
        overall_status = "THREAT DETECTED"
        message = "WARNING: Code is physically tampered or contains a malicious link."
    else:
        overall_status = "SECURE"
        message = "Both physical surface and digital link are verified authentic."
        
    return {
        "status": "Success",
        "overall_status": overall_status,
        "message": message,
        "scanned_url": extracted_url,
        "vision_layer": {
            "result": vision_verdict,
            "confidence": f"{v_confidence * 100:.2f}%"
        },
        "url_layer": {
            "result": url_verdict,
            "confidence": f"{url_confidence * 100:.2f}%",
            "explanation": url_explanation
        }
    }

# --- 4. DIRECT URL SCAN ENDPOINT ---
@app.post("/scan-url")
async def scan_url_direct(request: dict):
    """Scan a raw URL directly without a QR code image."""
    try:
        url = request.get("url", "").strip()

        if not url:
            raise HTTPException(status_code=400, detail="No URL provided.")

        if is_whitelisted(url):
            return {
                "status": "Success",
                "overall_status": "SECURE",
                "message": "This domain is on the trusted whitelist.",
                "scanned_url": url,
                "url_layer": {
                    "result": "SAFE",
                    "confidence": "0.00%",
                    "explanation": None
                }
            }

        url_features_df = extract_url_features(url)
        u_pred = url_model.predict_proba(url_features_df)[0][1]
        url_confidence = float(u_pred)
        url_verdict = "MALICIOUS" if url_confidence > 0.5 else "SAFE"

        url_explanation = None
        if url_verdict == "MALICIOUS":
            try:
                url_explanation = get_shap_explanation(url_features_df)
            except Exception as e:
                url_explanation = {"summary": "Explanation unavailable.", "risk_factors": []}

        overall_status = "THREAT DETECTED" if url_verdict == "MALICIOUS" else "SECURE"
        message = "WARNING: This link appears to be malicious." if url_verdict == "MALICIOUS" else "This link appears to be safe."

        return {
            "status": "Success",
            "overall_status": overall_status,
            "message": message,
            "scanned_url": url,
            "url_layer": {
                "result": url_verdict,
                "confidence": f"{url_confidence * 100:.2f}%",
                "explanation": url_explanation
            }
        }

    except Exception as e:
        return {
            "status": "Error",
            "message": f"Something went wrong: {str(e)}"
        }

print("AegisQ: Dual-Layer System Ready.")