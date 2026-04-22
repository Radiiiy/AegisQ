import tensorflow as tf
from tensorflow.keras.applications import MobileNetV2
from tensorflow.keras.layers import Dense, GlobalAveragePooling2D, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.preprocessing.image import ImageDataGenerator
import os

print("--- INITIALIZING AEGISQ VISION MODEL ---")

data_dir = "./dataset"
IMG_SIZE = (224, 224)
BATCH_SIZE = 32

# DATA AUGMENTATION - creates variations so model learns concepts not pixels
train_datagen = ImageDataGenerator(
    rescale=1./255,
    validation_split=0.2,
    rotation_range=15,
    width_shift_range=0.1,
    height_shift_range=0.1,
    brightness_range=[0.7, 1.3],
    horizontal_flip=True,
    zoom_range=0.1
)

val_datagen = ImageDataGenerator(
    rescale=1./255,
    validation_split=0.2
)

print("Step 1: Loading images with augmentation...")
train_dataset = train_datagen.flow_from_directory(
    data_dir,
    target_size=IMG_SIZE,
    batch_size=BATCH_SIZE,
    class_mode='binary',
    subset='training',
    seed=42
)

validation_dataset = val_datagen.flow_from_directory(
    data_dir,
    target_size=IMG_SIZE,
    batch_size=BATCH_SIZE,
    class_mode='binary',
    subset='validation',
    seed=42
)

print("Step 2: Building the MobileNetV2 Neural Network...")
base_model = MobileNetV2(input_shape=(224, 224, 3), include_top=False, weights='imagenet')
base_model.trainable = False

x = base_model.output
x = GlobalAveragePooling2D()(x)
x = Dense(128, activation='relu')(x)
x = Dropout(0.3)(x)  # DROPOUT - randomly ignores 30% of neurons during training to prevent memorization
predictions = Dense(1, activation='sigmoid')(x)

model = Model(inputs=base_model.input, outputs=predictions)

model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001),
    loss='binary_crossentropy',
    metrics=['accuracy']
)

print("Step 3: Training the AI...")
history = model.fit(
    train_dataset,
    validation_data=validation_dataset,
    epochs=15
)

print("Step 4: Saving the trained brain...")
model.save("aegis_cv_model.h5")
print("--- SUCCESS! Model saved as aegis_cv_model.h5 ---")