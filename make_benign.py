import qrcode
# A totally harmless, boring URL with no phishing keywords
harmless_url = "https://en.wikipedia.org/wiki/Computer_security"
img = qrcode.make(harmless_url)
img.save("dataset/clean/perfectly_safe_qr.png")
print("Saved perfectly_safe_qr.png!")