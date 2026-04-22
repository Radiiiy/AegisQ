import qrcode

print("--- FORGING DIGITAL PAYLOAD ---")

# A textbook phishing URL designed to trigger Layer 2's XGBoost math
# It has: http (not https), @ symbol, multiple hyphens, .xyz domain, and 5 keywords
malicious_url = "http://secure-login@verify-account-update.bank.xyz/token=1827364590"

print(f"Target URL: {malicious_url}")

# Generate a perfectly clean, high-quality QR code
img = qrcode.make(malicious_url)

# Save it
save_path = "dataset/clean/clean_phishing_qr.png"
img.save(save_path)

print(f"Success! Saved payload to {save_path}")