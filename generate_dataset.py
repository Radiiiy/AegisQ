import cv2
import numpy as np
import qrcode
import os

# Create folders
os.makedirs("dataset/clean", exist_ok=True)
os.makedirs("dataset/tampered", exist_ok=True)

def generate_clean_qr(url, filename):
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    clean_path = f"dataset/clean/{filename}.png"
    img.save(clean_path)
    return np.array(img)[:, :, ::-1].copy()

def apply_aggressive_tamper(cv_image, filename):
    tampered_img = cv_image.copy()
    h, w, _ = tampered_img.shape

    # 1. Obvious Physical Sticker (Target: 25% of the QR)
    # We use Bright Red or Solid Black to create high contrast
    size = int(w * 0.25) 
    x = np.random.randint(0, w - size)
    y = np.random.randint(0, h - size)
    
    color = (0, 0, 255) if np.random.random() > 0.5 else (0, 0, 0)
    cv2.rectangle(tampered_img, (x, y), (x + size, y + size), color, -1)

    # 2. Heavy Edge Blur (Simulates a physical sticker's shadow/edge)
    tampered_img = cv2.GaussianBlur(tampered_img, (11, 11), 0)

    # Save
    tampered_path = f"dataset/tampered/{filename}_tampered.png"
    cv2.imwrite(tampered_path, tampered_img)

# --- Generate 2000 Images ---
base_urls = ["https://www.lankapay.net", "https://www.boc.lk", "https://www.sampath.lk"]
print("Generating Aggressive Threat Dataset...")

for i in range(1000):
    url = base_urls[i % len(base_urls)] + f"/verify/{i}"
    name = f"qr_v3_{i}"
    clean = generate_clean_qr(url, name)
    apply_aggressive_tamper(clean, name)

print("✅ Dataset Reset Complete.")