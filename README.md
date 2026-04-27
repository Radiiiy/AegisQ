# AegisQ – AI-Driven QR Transaction Verification & Fraud Detection System

## Live Demo
Access AegisQ live at: https://web-production-4d4625.up.railway.app/app

## Overview
AegisQ is a dual-layer AI security system designed to protect users from QR code-based 
phishing attacks (quishing) in Sri Lanka. It combines computer vision and machine learning 
to analyze both the physical integrity of QR codes and the safety of embedded URLs in real time.

## System Architecture
- **Layer 1 – Vision Analysis (CNN):** Uses MobileNetV2 to detect physical tampering on QR codes
- **Layer 2 – URL Analysis (XGBoost):** Analyzes embedded URLs using 10 heuristic features
- **SHAP Explainability:** Provides human-readable explanations for every threat detection
- **Whitelist System:** Trusted Sri Lankan domains bypass AI analysis automatically
- **Direct URL Scanning:** Analyze any suspicious link without a QR code

## Features
- Real-time QR code scanning and threat detection
- Physical tampering detection (sticker overlays, synthetic reproductions)
- Phishing URL detection with explainable AI reasoning
- Sinhala/Tamil localization for Sri Lankan phishing patterns
- Domain whitelist for trusted Sri Lankan financial institutions
- Direct URL scanning via paste or manual input
- Scan history tracking

## Tech Stack
- **Backend:** Python, FastAPI, Uvicorn
- **AI Models:** TensorFlow/Keras (MobileNetV2 CNN), XGBoost
- **Explainability:** SHAP (SHapley Additive exPlanations)
- **Frontend:** HTML, CSS, JavaScript
- **Database:** PostgreSQL

## Model Performance
| Model | Accuracy | F1-Score |
|-------|----------|----------|
| CNN (Physical Tampering) | ~99.91% on test images | - |
| XGBoost (URL Analysis) | 96.92% | 0.97 |

## How The OR Gate Works
AegisQ uses a Boolean OR Gate to combine both AI layers into one final verdict.
Think of it like a two-scanner security checkpoint — if either scanner raises an alarm, 
you don't get through. Both must say safe to pass.

If Layer 1 says DANGEROUS   →  THREAT DETECTED (regardless of Layer 2)
If Layer 2 says MALICIOUS   →  THREAT DETECTED (regardless of Layer 1)
If BOTH say SAFE            →  SECURE

This means even if one layer can't check something (e.g. a tampered QR code where 
the URL can't be read), the other layer can still catch the threat.

**Real example from testing:**
Tampered QR with no readable URL:
Layer 1: DANGEROUS (99.91%)  ← caught it
Layer 2: UNKNOWN (no URL)    ← couldn't check
OR Gate: THREAT DETECTED ✅

An AND Gate would have missed this — requiring BOTH layers to flag something 
before blocking it. OR Gate is safer because either layer catching a threat is enough.

---

## Key Research Findings

### Finding 1 — False Positive Problem & Whitelist Solution
During testing, legitimate Sri Lankan payment domains such as `lankapay.net` were 
incorrectly flagged as malicious due to regional keywords like `lanka` and `verify` 
appearing in the URL. This revealed a critical limitation of generic keyword-based 
detection when applied to regional contexts.

**Solution:** A domain whitelist of trusted Sri Lankan financial institutions was 
implemented. Whitelisted domains bypass AI analysis entirely and are immediately 
returned as SECURE. This eliminated false positives for legitimate platforms while 
maintaining full AI analysis for unknown domains.

**Lesson:** Generic phishing detection models cannot be directly applied to regional 
contexts without localization. This finding directly motivated the whitelist feature 
and the Sinhala/Tamil localization work.

### Finding 2 — Localization Feature Limitation
The Sinhala/Tamil keyword detection feature was implemented and integrated into the 
detection pipeline as a 10th feature alongside the existing 9 URL heuristics. However, 
evaluation revealed that due to the scarcity of Sri Lanka-specific phishing samples in 
publicly available datasets such as PhishTank and OpenPhish, the model assigns lower 
weight to Sinhala/Tamil keyword signals compared to universal phishing indicators like 
HTTPS usage and URL entropy.

**Implication:** The feature is correctly implemented and contributes to detection, 
but requires a dedicated regional phishing dataset containing Sri Lankan language 
patterns to become a dominant signal. This is identified as a key area for future work.

**Lesson:** Building effective regional cybersecurity tools requires regional training 
data — a resource that currently does not exist for Sri Lanka. AegisQ's localization 
framework provides the foundation for this when such data becomes available.

---

## Setup Instructions
1. Install dependencies: `pip install -r requirements.txt`
2. Run feature extraction: `python extract_features_v2.py`
3. Train URL model: `python train_url_final.py`
4. Train CNN model: `python train_cnn.py`
5. Start server: `uvicorn main:app --reload`

## Project Status
- [x] Dual-layer AI backend
- [x] SHAP explainability
- [x] Direct URL scanning
- [x] Sinhala/Tamil localization
- [x] Domain whitelist
- [x] Key research findings documented
- [ ] Scan history
- [ ] Web frontend

## Author
Radeen Amarabandu | BSc(Hons) Computer Security | University of Plymouth (NSBM)