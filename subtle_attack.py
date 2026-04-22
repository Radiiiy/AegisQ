import qrcode
import cv2
import numpy as np

print("--- FORGING SUBTLE EVASION PAYLOAD ---")

# 1. The Malicious Link
malicious_url = "http://secure-update-login.boc-bank.xyz/auth=99281"
qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
qr.add_data(malicious_url)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

# Convert to OpenCV format
cv_img = np.array(img)[:, :, ::-1].copy()
h, w, _ = cv_img.shape

# 2. The "Subtle" Tamper (Only 5% of the image!)
size = int(w * 0.05) 
x, y = int(w * 0.5), int(h * 0.5) # Put it right in the middle
cv2.rectangle(cv_img, (x, y), (x + size, y + size), (0, 0, 0), -1) # Tiny black square

save_path = "dataset/tampered/subtle_attack_qr.png"
cv2.imwrite(save_path, cv_img)
print(f"Saved tiny-sticker payload to {save_path}")