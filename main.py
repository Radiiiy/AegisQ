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
from database import init_db, save_scan, get_history, get_stats
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()
init_db()
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/app")
def serve_frontend():
    return FileResponse("index2.html")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    """Translates a URL string into 13 features the XGBoost model expects."""
    url = str(url)
    ext = tldextract.extract(url)
    domain_name = ext.domain.lower()
    raw_entropy = _calculate_entropy(url)

    suspicious_tlds = ['zip', 'top', 'xyz', 'work', 'bid', 'click']
    safe_tlds = ['com', 'org', 'net', 'edu', 'gov', 'ac', 'lk',
                 'uk', 'au', 'io', 'google', 'youtube', 'microsoft']
    trusted_domains_list = [
        'google', 'youtube', 'facebook', 'instagram', 'twitter',
        'microsoft', 'apple', 'amazon', 'netflix', 'spotify',
        'github', 'stackoverflow', 'wikipedia', 'reddit', 'linkedin',
        'whatsapp', 'telegram', 'tiktok', 'snapchat', 'pinterest',
        'paypal', 'stripe', 'wise', 'revolut', 'coinbase',
        'booking', 'airbnb', 'tripadvisor', 'expedia', 'uber',
        'bbc', 'cnn', 'reuters', 'bloomberg', 'nytimes',
        'udemy', 'coursera', 'edx', 'khanacademy', 'duolingo',
        'notion', 'figma', 'canva', 'discord', 'slack',
        'dialog', 'mobitel', 'slt', 'hutch', 'airtel',
        'boc', 'sampath', 'combank', 'hnb', 'nsbm', 'cmb', 'seylan',
        'dfcc', 'nations', 'peoples', 'lankapay', 'lankaqr', 'cbsl',
        'ikman', 'daraz', 'pickme', 'takas', 'kapruka',
        'gov', 'edu', 'ac', 'university', 'bank', 'nasa', 'who'
    ]

    keywords = ['login', 'verify', 'secure', 'update', 'banking',
                'lanka', 'gift', 'reward']
    transliterated_keywords = [
        'ginuma', 'tahauru', 'bank seva', 'ganum', 'within',
        'ithiripas', 'palamu', 'anuthura', 'sampurna',
        'kanakku', 'saripaaru', 'vangki', 'payam', 'pudhuppi',
        'uruthipaduthu', 'seluththu', 'vagaiyara',
        'prize winner', 'congratulations winner', 'claim reward',
        'account suspended', 'urgent action', 'immediate verify'
    ]

    is_https = 1 if url.startswith('https') else 0
    suspicious_tld = 1 if ext.suffix in suspicious_tlds else 0
    safe_tld = 1 if ext.suffix in safe_tlds else 0
    is_trusted_domain = 1 if (
        any(td in domain_name for td in trusted_domains_list) or
        any(td in ext.suffix for td in trusted_domains_list)
    ) else 0
    sinhala_tamil_unicode = any(
        '\u0D80' <= char <= '\u0DFF' or '\u0B80' <= char <= '\u0BFF'
        for char in url
    )

    features = {
        'url_length':             len(url),
        'digit_ratio':            sum(c.isdigit() for c in url) / len(url),
        'entropy':                raw_entropy,
        'count_dots':             url.count('.'),
        'count_hyphens':          url.count('-'),
        'count_at':               url.count('@'),
        'is_https':               is_https,
        'suspicious_tld':         suspicious_tld,
        'safe_tld':               safe_tld,
        'is_trusted_domain':      is_trusted_domain,
        'keyword_count':          sum(1 for word in keywords if word in url.lower()),
        'sinhala_tamil_keywords': (1 if sinhala_tamil_unicode else 0)
                                  + sum(1 for word in transliterated_keywords if word in url.lower()),
        'entropy_risk':           1 if (
                                      raw_entropy > 4.5
                                      and suspicious_tld == 1
                                      and is_https == 0
                                      and is_trusted_domain == 0
                                  ) else 0,
    }

    return pd.DataFrame([features])

def is_whitelisted(url):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    return domain in trusted_domains

# --- 3. SHAP EXPLANATION ---
_FEATURE_REASONS = {
    'url_length':    "The URL is unusually long, a common tactic to hide a malicious destination.",
    'digit_ratio':   "The URL's digit pattern matches known phishing link structures.",
    'entropy':       "The URL has high character randomness, suggesting an obfuscated or machine-generated address.",
    'count_dots':    "The URL contains an excessive number of dots, often used to fake legitimate subdomains.",
    'count_hyphens': "The URL contains many hyphens, commonly used to mimic trusted brand names.",
    'count_at':      "The URL contains an @ symbol, which can be used to disguise the true destination.",
    'is_https':      "The URL does not use HTTPS, meaning the connection is unencrypted and unverified.",
    'suspicious_tld':"The URL uses a suspicious top-level domain commonly associated with phishing sites.",
    'keyword_count': "The URL contains phishing keywords such as 'login', 'verify', or 'secure'.",
    'sinhala_tamil_keywords': "The URL contains Sinhala or Tamil language patterns commonly used in Sri Lankan phishing scams.",
    'safe_tld': "The URL does not use a trusted domain extension, increasing suspicion.",
    'is_trusted_domain': "The URL does not belong to any recognised trusted domain, increasing suspicion.",
    'entropy_risk': "The URL has high randomness combined with multiple other suspicious signals.",
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
        if impact <= 0.01:
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
    if 0.3 <= v_confidence <= 0.7:
        vision_verdict = "UNCERTAIN"
    elif v_confidence > 0.7:
        vision_verdict = "DANGEROUS"
    else:
        vision_verdict = "SAFE"
    
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
    # UNCERTAIN vision is abstained — only explicit DANGEROUS or MALICIOUS triggers a threat.
    if vision_verdict == "DANGEROUS" or url_verdict == "MALICIOUS":
        overall_status = "THREAT DETECTED"
        message = "WARNING: Code is physically tampered or contains a malicious link."
    elif vision_verdict == "UNCERTAIN" and url_verdict == "UNKNOWN":
        overall_status = "UNVERIFIED"
        message = "Could not reliably verify this QR code. Please try a clearer image or use the live camera scan."
    elif vision_verdict == "UNCERTAIN" and url_verdict == "SAFE":
        overall_status = "SECURE"
        message = "Physical integrity could not be verified, but the digital link appears safe."
    else:
        overall_status = "SECURE"
        message = "Both physical surface and digital link are verified authentic."
    # Save to scan history
    explanation_summary = None
    if url_explanation:
        explanation_summary = url_explanation.get("summary", None)

    save_scan(
        scan_type="QR_IMAGE",
        scanned_url=extracted_url,
        overall_status=overall_status,
        vision_result=vision_verdict,
        vision_confidence=v_confidence,
        url_result=url_verdict,
        url_confidence=url_confidence,
        explanation_summary=explanation_summary
    )                       
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

                # Save to scan history
        explanation_summary = None
        if url_explanation:
            explanation_summary = url_explanation.get("summary", None)

        save_scan(
            scan_type="DIRECT_URL",
            scanned_url=url,
            overall_status=overall_status,
            vision_result="N/A",
            vision_confidence=0.0,
            url_result=url_verdict,
            url_confidence=url_confidence,
            explanation_summary=explanation_summary
        )

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
# --- 5. SCAN HISTORY ENDPOINT ---
@app.get("/history")
def scan_history(limit: int = 50):
    """Returns the most recent scan history."""
    records = get_history(limit)
    return {
        "status": "Success",
        "total_returned": len(records),
        "scans": [
            {
                "id": r.id,
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_type": r.scan_type,
                "scanned_url": r.scanned_url,
                "overall_status": r.overall_status,
                "vision_result": r.vision_result,
                "vision_confidence": f"{r.vision_confidence * 100:.2f}%",
                "url_result": r.url_result,
                "url_confidence": f"{r.url_confidence * 100:.2f}%",
                "explanation_summary": r.explanation_summary
            }
            for r in records
        ]
    }

# --- 6. STATS ENDPOINT ---
@app.get("/stats")
def scan_stats():
    """Returns overall scanning statistics."""
    return {
        "status": "Success",
        "statistics": get_stats()
    }
print("AegisQ: Dual-Layer System Ready.")