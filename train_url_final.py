import pandas as pd
import xgboost as xgb
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("--- AEGISQ: FORGING THE FINAL URL BRAIN ---")

# 1. Load REAL phishing URL features (extracted from 56k real phishing URLs)
print("Step 1: Loading real phishing URL features...")
phish_features = pd.read_csv("url_features_numeric_v2.csv")
phish_features['is_phishing'] = 1
print(f"Real phishing samples: {len(phish_features)}")

# 2. Generate synthetic SAFE URL features
print("Step 2: Generating safe URL features...")
np.random.seed(42)
n_safe = len(phish_features)  # Match the number of phishing samples

safe_features = pd.DataFrame({
    'url_length': np.random.randint(20, 75, n_safe),
    'digit_ratio': np.random.uniform(0.0, 0.08, n_safe),
    'entropy': np.random.uniform(3.5, 4.5, n_safe),
    'count_dots': np.random.randint(1, 4, n_safe),
    'count_hyphens': np.random.randint(0, 2, n_safe),
    'count_at': np.zeros(n_safe),
    'is_https': np.ones(n_safe),
    'suspicious_tld': np.zeros(n_safe),
    'keyword_count': np.random.randint(0, 2, n_safe),
    'sinhala_tamil_keywords': np.zeros(n_safe),
    'is_phishing': 0
})
print(f"Synthetic safe samples: {len(safe_features)}")

# 3. Combine real phishing + synthetic safe
data = pd.concat([phish_features, safe_features], ignore_index=True)

feature_columns = [
    'url_length', 'digit_ratio', 'entropy', 'count_dots',
    'count_hyphens', 'count_at', 'is_https', 'suspicious_tld',
    'keyword_count', 'sinhala_tamil_keywords'
]

X = data[feature_columns]
y = data['is_phishing']

print(f"Total samples: {len(X)}")
print(f"Malicious: {int(y.sum())} | Safe: {int(len(y) - y.sum())}")

# 4. Split into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 5. Train XGBoost
print("Step 3: Training XGBoost on combined dataset...")
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
print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))

# 7. Save
with open("aegis_url_model_v2.pkl", "wb") as f:
    pickle.dump(model, f)

print("--- SUCCESS: Aegis URL Brain trained and saved! ---")