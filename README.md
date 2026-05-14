# AegisQ — AI-Driven QR Transaction Verification & Fraud Detection System

## Live Demo
Access AegisQ live at: https://web-production-4d4625.up.railway.app/app

## Overview
AegisQ is a dual-layer AI security system that protects users from QR code-based phishing attacks (quishing). It combines computer vision and machine learning to analyse both the physical integrity of QR codes and the safety of embedded URLs in real time. The system was developed as a final year BSc Computer Security project, using Sri Lanka as a primary case study for emerging digital payment markets.

## System Architecture
- **Layer 1 — Vision Analysis (CNN):** MobileNetV2 detects physical tampering on QR code images
- **Layer 2 — URL Analysis (XGBoost):** Analyses embedded URLs using 13 heuristic features
- **SHAP Explainability:** Provides human-readable risk factor explanations for every threat detection
- **Smart Whitelist System:** 50,000 globally ranked domains plus trusted TLD verification (.lk, .gov, .edu)
- **Live Camera Scanning:** Real-time QR code scanning via device camera
- **Direct URL Scanning:** Analyse any suspicious link without a QR code image
- **Abstention Logic:** Returns UNVERIFIED when CNN confidence is between 30-70% instead of wrong verdict

## Features
- Live camera QR code scanning using html5-qrcode library
- QR image upload for full dual-layer physical and digital analysis
- Direct URL checker for links received via messaging apps
- Physical tampering detection (sticker overlays, blur patches, colour overlays)
- Phishing URL detection with explainable AI reasoning
- Sinhala/Tamil localisation for Sri Lankan phishing patterns
- Smart domain whitelist with 50,000 Tranco top domains
- Scan history and statistics tracking
- Progressive Web App — installable on mobile devices
- Cloud deployed on Railway with permanent HTTPS URL

## Tech Stack
- **Backend:** Python, FastAPI, Uvicorn
- **AI Models:** TensorFlow/Keras (MobileNetV2 CNN), XGBoost
- **Explainability:** SHAP (SHapley Additive exPlanations)
- **Frontend:** HTML, CSS, JavaScript (PWA)
- **Database:** SQLite via SQLAlchemy
- **Deployment:** Railway cloud infrastructure

## Model Performance
| Model | Accuracy | F1-Score |
|-------|----------|----------|
| CNN (Physical Tampering) | 99.91% on test dataset | — |
| XGBoost (URL Analysis) | 96.41% | 0.96 |

## Adversarial Robustness Testing
| Attack Category | Test Cases | Detection Rate |
|----------------|------------|----------------|
| Homoglyph Attacks | 5/5 | 100% |
| Subdomain Padding | 5/5 | 100% |
| Keyword Evasion | 5/5 | 100% |
| Zero-Day Domains | 5/5 | 100% |
| Legitimate URL Resilience | 8/8 | 100% |
| Sinhala/Tamil Localisation | 3/3 | 100% |
| **Overall** | **31/31** | **100%** |

## How The OR Gate Works
AegisQ uses a Boolean OR Gate to combine both AI layers into a single final verdict.

```
if vision_verdict == "DANGEROUS" or url_verdict == "MALICIOUS":
    overall_status = "THREAT DETECTED"
elif vision_verdict == "UNCERTAIN" and url_verdict == "UNKNOWN":
    overall_status = "UNVERIFIED"
elif vision_verdict == "UNCERTAIN" and url_verdict == "SAFE":
    overall_status = "SECURE"
else:
    overall_status = "SECURE"
```

If either layer detects a threat, the overall verdict is THREAT DETECTED. Both layers must confirm safe for a SECURE result. If the CNN is uncertain and no URL is found, the system returns UNVERIFIED rather than a potentially wrong verdict.

## Key Research Findings

### Finding 1 — False Positives on Regional Domains
Generic phishing keywords such as `lanka` and `verify` appear naturally in legitimate Sri Lankan payment URLs, causing initial false positives on platforms including LankaPay. Resolved through a multi-layer whitelist system incorporating explicit trusted domains, smart TLD trust for .lk HTTPS domains, and the top 50,000 globally ranked Tranco domains.

### Finding 2 — High Entropy Token False Positives
Legitimate URLs containing randomly generated session tokens (e.g. Google sharing links) were initially flagged due to high entropy scores. Resolved by implementing a composite `entropy_risk` feature that only triggers when high entropy is combined with multiple other suspicious signals.

### Finding 3 — Localisation Feature Limitation
The Sinhala/Tamil keyword detection feature was implemented but has limited influence due to the absence of Sri Lanka-specific phishing samples in publicly available datasets. Identified as a key area for future work requiring a dedicated regional phishing dataset.

### Finding 4 — Vision Model Domain Gap
The CNN physical integrity layer was trained on standard square-pixel QR codes. Real-world QR codes with circular dot patterns, rounded finder elements, and embedded logos produced false positives. Mitigated through the abstention logic and live camera scanning which bypasses the vision layer entirely.

## Setup Instructions

**Prerequisites:** Python 3.9 or above

**Installation:**
```
git clone https://github.com/Radiiiy/AegisQ
cd AegisQ
pip install -r requirements.txt
```

**Starting the server:**
```
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Accessing the system:**
```
http://127.0.0.1:8000/app
```

## Project Status
- [x] Dual-layer AI backend
- [x] SHAP explainability
- [x] Live camera QR scanning
- [x] QR image upload
- [x] Direct URL scanning
- [x] Sinhala/Tamil localisation
- [x] Smart domain whitelist (50,000 domains)
- [x] Scan history and statistics
- [x] Abstention logic for uncertain predictions
- [x] Progressive Web App frontend
- [x] Railway cloud deployment
- [x] Adversarial robustness testing (31/31 100%)

## Author
Radeen Amarabandu | BSc(Hons) Computer Security | University of Plymouth (NSBM)
