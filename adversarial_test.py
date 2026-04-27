import requests
import json

API = "http://127.0.0.1:8000/scan-url"

def test_url(url, expected, category):
    r = requests.post(API, json={"url": url})
    d = r.json()
    status = d["overall_status"]
    correct = "✅" if status == expected else "❌"
    print(f"{correct} [{category}] {status} | {url[:70]}")
    return 1 if status == expected else 0

print("=" * 70)
print("AEGISQ ADVERSARIAL ROBUSTNESS EVALUATION")
print("=" * 70)

results = {}

# ── CATEGORY 1: HOMOGLYPH ATTACKS ──
# Replacing real letters with visually identical unicode characters
print("\n[1] HOMOGLYPH ATTACKS (should be THREAT DETECTED)")
cat = "Homoglyph"
scores = []
scores.append(test_url("http://paypaI.com/login", "THREAT DETECTED", cat))        # capital I instead of l
scores.append(test_url("http://g00gle.com/verify", "THREAT DETECTED", cat))       # zeros instead of o
scores.append(test_url("http://arnazon.com/secure", "THREAT DETECTED", cat))      # rn instead of m
scores.append(test_url("http://faceb00k.com/login", "THREAT DETECTED", cat))      # zeros instead of o
scores.append(test_url("http://rnicrosofт.com/update", "THREAT DETECTED", cat))   # Cyrillic т
results["Homoglyph Attacks"] = scores

# ── CATEGORY 2: SUBDOMAIN PADDING ──
# Using legitimate brand names as subdomains to appear trustworthy
print("\n[2] SUBDOMAIN PADDING (should be THREAT DETECTED)")
cat = "Subdomain"
scores = []
scores.append(test_url("http://paypal.com.evil-site.xyz/login", "THREAT DETECTED", cat))
scores.append(test_url("http://google.com.phishing.top/verify", "THREAT DETECTED", cat))
scores.append(test_url("http://boc.lk.fake-bank.xyz/account", "THREAT DETECTED", cat))
scores.append(test_url("http://lankapay.lk.scam.click/pay", "THREAT DETECTED", cat))
scores.append(test_url("http://dialog.lk.update.work/secure", "THREAT DETECTED", cat))
results["Subdomain Padding"] = scores

# ── CATEGORY 3: KEYWORD EVASION ──
# Malicious URLs deliberately avoiding trigger keywords
print("\n[3] KEYWORD EVASION (should be THREAT DETECTED)")
cat = "Evasion"
scores = []
scores.append(test_url("http://xn--pypal-4ve.com/enter", "THREAT DETECTED", cat))
scores.append(test_url("http://credential-harvest.xyz/portal", "THREAT DETECTED", cat))
scores.append(test_url("http://user-auth.click/redirect", "THREAT DETECTED", cat))
scores.append(test_url("http://data-submit.work/form", "THREAT DETECTED", cat))
scores.append(test_url("http://info-grab.top/collect", "THREAT DETECTED", cat))
results["Keyword Evasion"] = scores

# ── CATEGORY 4: ZERO DAY DOMAINS ──
# Newly created suspicious domains with no history
print("\n[4] ZERO-DAY DOMAINS (should be THREAT DETECTED)")
cat = "Zero-Day"
scores = []
scores.append(test_url("http://secure-pay-2024.xyz/verify", "THREAT DETECTED", cat))
scores.append(test_url("http://bank-update-now.top/login", "THREAT DETECTED", cat))
scores.append(test_url("http://free-reward-claim.click/gift", "THREAT DETECTED", cat))
scores.append(test_url("http://account-suspended-fix.work/restore", "THREAT DETECTED", cat))
scores.append(test_url("http://urgent-verify-now.zip/confirm", "THREAT DETECTED", cat))
results["Zero-Day Domains"] = scores

# ── CATEGORY 5: LEGITIMATE URL RESILIENCE ──
# Making sure real URLs still pass after adversarial training
print("\n[5] LEGITIMATE URL RESILIENCE (should be SECURE)")
cat = "Legitimate"
scores = []
scores.append(test_url("https://www.facebook.com/login", "SECURE", cat))
scores.append(test_url("https://accounts.google.com/signin/verify", "SECURE", cat))
scores.append(test_url("https://www.paypal.com/signin", "SECURE", cat))
scores.append(test_url("https://www.dialog.lk/secure-payment", "SECURE", cat))
scores.append(test_url("https://www.nsbm.ac.lk/students/portal", "SECURE", cat))
scores.append(test_url("https://www.amazon.com/dp/B09V3KXJPB", "SECURE", cat))
scores.append(test_url("https://www.ndbbank.com/account/update", "SECURE", cat))
scores.append(test_url("https://share.google/rFtMCYZBWGYIoKesD", "SECURE", cat))
results["Legitimate Resilience"] = scores

# ── CATEGORY 6: SINHALA/TAMIL LOCALIZATION ──
print("\n[6] SINHALA/TAMIL LOCALIZATION (should be THREAT DETECTED)")
cat = "Localization"
scores = []
scores.append(test_url("http://ginuma-tahauru.xyz/kanakku/verify", "THREAT DETECTED", cat))
scores.append(test_url("http://bank-seva-update.top/ganum", "THREAT DETECTED", cat))
scores.append(test_url("http://claim-reward-gift.xyz/prize-winner", "THREAT DETECTED", cat))
results["Sinhala/Tamil Localization"] = scores

# ── SUMMARY ──
print("\n" + "=" * 70)
print("EVALUATION SUMMARY")
print("=" * 70)
total_correct = 0
total_tests = 0
for category, scores in results.items():
    correct = sum(scores)
    total = len(scores)
    rate = correct / total * 100
    total_correct += correct
    total_tests += total
    print(f"{category:30s} {correct}/{total} ({rate:.0f}%)")

overall = total_correct / total_tests * 100
print(f"\nOVERALL DETECTION RATE: {total_correct}/{total_tests} ({overall:.1f}%)")
print("=" * 70)