import tensorflow as tf
import cv2
import numpy as np

print("--- AEGISQ TRUTH SERUM DIAGNOSTIC ---")
# 1. Load the model directly
model = tf.keras.models.load_model('aegis_cv_model.h5')

# We will test both a tampered and a clean image
tampered_path = "dataset/tampered/qr_v3_1_tampered.png"
clean_path = "dataset/clean/qr_v3_1.png" # Assuming this exists

def test_image(image_path, label_name):
    # Load using pure Keras (exactly how it was trained)
    img_keras = tf.keras.preprocessing.image.load_img(image_path, target_size=(224, 224))
    img_array = tf.keras.preprocessing.image.img_to_array(img_keras) / 255.0
    img_batch = np.expand_dims(img_array, axis=0)
    
    # Get the raw score
    score = model.predict(img_batch, verbose=0)[0][0]
    print(f"{label_name} Image Raw Score: {score:.4f}")

try:
    test_image(tampered_path, "TAMPERED")
    test_image(clean_path, "CLEAN")
except Exception as e:
    print(f"Error loading images: {e}. Check your file paths!")