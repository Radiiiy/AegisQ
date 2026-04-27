import pandas as pd
import xgboost as xgb
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("--- AEGISQ: FORGING THE FINAL URL BRAIN v3 ---")

# 1. Load REAL phishing URL features
print("Step 1: Loading real phishing URL features...")
phish_features = pd.read_csv("url_features_numeric_v2.csv")
phish_features['is_phishing'] = 1
print(f"Real phishing samples: {len(phish_features)}")

# 2. Load safe URL features from CSV
print("Step 2: Loading safe URL features from safe_url_features.csv...")
safe_features = pd.read_csv("safe_url_features.csv")
safe_features['is_phishing'] = 0
print(f"Real safe samples: {len(safe_features)}")

# 3. Combine
data = pd.concat([phish_features, safe_features], ignore_index=True)

feature_columns = [
    'url_length', 'digit_ratio', 'entropy', 'count_dots',
    'count_hyphens', 'count_at', 'is_https', 'suspicious_tld',
    'safe_tld', 'is_trusted_domain', 'keyword_count',
    'sinhala_tamil_keywords', 'entropy_risk'
]

X = data[feature_columns]
y = data['is_phishing']

print(f"Total samples: {len(X)}")
print(f"Malicious: {int(y.sum())} | Safe: {int(len(y) - y.sum())}")

# 4. Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 5. Train
print("Step 3: Training XGBoost on realistic dataset...")
model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    random_state=42
)
model.fit(X_train, y_train)

# 6. Evaluate
print("Step 4: Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
print(classification_report(y_test, y_pred, 
      target_names=['Safe', 'Malicious']))

# 7. Save
with open("aegis_url_model_v2.pkl", "wb") as f:
    pickle.dump(model, f)

print("--- SUCCESS: Realistic URL Brain trained and saved! ---")