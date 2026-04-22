import tensorflow as tf
import numpy as np
import cv2
import os

model = tf.keras.models.load_model('aegis_cv_model.h5')
test_path = "dataset/tampered/"
files = os.listdir(test_path)[:5] # Test first 5 images

print("--- VISION DIAGNOSTIC MODE ---")
for f in files:
    img = cv2.imread(os.path.join(test_path, f))
    img = cv2.resize(img, (224, 224)) / 255.0
    pred = model.predict(np.expand_dims(img, axis=0))[0][0]
    
    # This prints the RAW number before the 'Safe/Dangerous' label
    print(f"File: {f} | Raw Score: {pred:.4f} | {'FAILED' if pred < 0.5 else 'PASSED'}")