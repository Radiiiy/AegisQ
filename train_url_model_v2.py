import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle
import numpy as np

print("--- AEGISQ: TRAINING BALANCED URL MODEL ---")

# 1. Load v2 Features
phish_data = pd.read_csv("url_features_numeric_v2.csv")
phish_data['is_phishing'] = 1

# Dynamically count how many phishing rows we have
num_phishing_rows = len(phish_data)
print(f"Loaded {num_phishing_rows} phishing URLs from dataset.")

# 2. Create REALISTIC 'Safe' Data
# We broaden the ranges so the AI doesn't panic at normal websites
safe_data = pd.DataFrame({
    'url_length': np.random.randint(15, 120, num_phishing_rows), # Safe links can be up to 120 chars!
    'digit_ratio': np.random.uniform(0, 0.1, num_phishing_rows),
    'entropy': np.random.uniform(3.0, 4.8, num_phishing_rows),
    'count_dots': np.random.randint(1, 5, num_phishing_rows),    # Allow up to 4 dots (like www.domain.co.uk)
    'count_hyphens': np.random.randint(0, 4, num_phishing_rows), # Allow hyphens
    'count_at': 0,
    'is_https': 1, # Safe sites almost always use HTTPS
    'suspicious_tld': 0,
    'keyword_count': np.random.randint(0, 2, num_phishing_rows), # Allow 0 or 1 keywords (like 'secure')
    'is_phishing': 0
})

print(f"Generated {num_phishing_rows} realistic safe URLs for perfect balance.")

# Combine them
data = pd.concat([phish_data, safe_data], ignore_index=True)
X = data.drop('is_phishing', axis=1)
y = data['is_phishing']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train
url_model = xgb.XGBClassifier(n_estimators=200, max_depth=7, learning_rate=0.05)
url_model.fit(X_train, y_train)

# 4. Final Accuracy Check
accuracy = accuracy_score(y_test, url_model.predict(X_test))
print(f"🔥 NEW Balanced Model Accuracy: {accuracy * 100:.2f}%")

# Save updated brain
with open("aegis_url_model_v2.pkl", "wb") as f:
    pickle.dump(url_model, f)
    
print("--- SUCCESS: Aegis URL Brain Updated ---")