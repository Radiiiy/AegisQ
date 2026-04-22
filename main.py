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
            "confidence": f"{url_confidence * 100:.2f}%"
        }
    }

print("AegisQ: Dual-Layer System Ready.")