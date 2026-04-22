import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle
import numpy as np

print("--- AEGISQ: TRAINING URL ANALYSIS MODEL ---")

# 1. Load the Phishing features from Phase 1
print("Step 1: Loading phishing patterns...")
phish_data = pd.read_csv("url_features_numeric.csv")
phish_data['is_phishing'] = 1  # Label these as 'Dangerous'

# 2. Create 'Safe' data to balance the AI (using your whitelist logic)
print("Step 2: Generating safe patterns for comparison...")
# We'll create 1000 safe examples that look like your whitelist domains
safe_data = pd.DataFrame({
    'url_length': np.random.randint(15, 30, 1000),
    'count_dots': np.random.randint(1, 3, 1000),
    'count_hyphens': 0,
    'count_at': 0,
    'count_question': 0,
    'is_https': 1,
    'keyword_count': 0,
    'is_phishing': 0  # Label these as 'Safe'
})

# Combine them into one training set
data = pd.concat([phish_data, safe_data], ignore_index=True)

# 3. Prepare for training
X = data.drop('is_phishing', axis=1) # Features (The numbers)
y = data['is_phishing']              # Answers (Safe vs Phishing)

# Split into 80% learning / 20% testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Step 3: Training the XGBoost Classifier...")
# We use XGBoost because it's the state-of-the-art for URL detection [cite: 93]
url_model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    eval_metric='logloss'
)

url_model.fit(X_train, y_train)

# 4. Accuracy Check
predictions = url_model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# 5. Save the Brain
with open("aegis_url_model.pkl", "wb") as f:
    pickle.dump(url_model, f)

print("--- SUCCESS: URL Model saved as aegis_url_model.pkl ---")