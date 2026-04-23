import pandas as pd
import xgboost as xgb
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("--- AEGISQ: FORGING THE FINAL URL BRAIN v3 ---")

# 1. Load REAL phishing URL features
print("Step 1: Loading real phishing URL features...")
phish_features = pd.read_csv("url_features_numeric_v2.csv")
phish_features['is_phishing'] = 1
print(f"Real phishing samples: {len(phish_features)}")

# 2. Generate REALISTIC safe URL features
# These now reflect real world legitimate URLs properly
print("Step 2: Generating realistic safe URL features...")
np.random.seed(42)
n_safe = len(phish_features)

safe_features = pd.DataFrame({
    # Real URLs vary widely in length including long ones with IDs
    'url_length': np.random.randint(20, 120, n_safe),
    
    # Real URLs CAN have digits - IDs, dates, version numbers
    # This is the key fix - safe URLs can have high digit ratios
    'digit_ratio': np.random.uniform(0.0, 0.35, n_safe),
    
    # Real URLs have normal entropy - not extreme
    'entropy': np.random.uniform(3.2, 4.8, n_safe),
    
    # Real URLs can have multiple dots - subdomains like students.nsbm.ac.lk
    'count_dots': np.random.randint(1, 6, n_safe),
    
    # Real URLs rarely have many hyphens
    'count_hyphens': np.random.randint(0, 2, n_safe),
    
    # Legitimate URLs never use @ symbol
    'count_at': np.zeros(n_safe),
    
    # Legitimate sites use HTTPS
    'is_https': np.ones(n_safe),
    
    # Legitimate sites don't use suspicious TLDs
    'suspicious_tld': np.zeros(n_safe),
    
    # Legitimate sites rarely have phishing keywords
    'keyword_count': np.random.randint(0, 2, n_safe),
    
    # Legitimate Sri Lankan sites don't use Sinhala/Tamil scam patterns
    'sinhala_tamil_keywords': np.zeros(n_safe),

    # Legitimate sites use common safe TLDs
    'safe_tld': np.ones(n_safe),

    # Legitimate sites belong to recognised domains
    'is_trusted_domain': np.ones(n_safe),

    # Legitimate sites don't trigger composite entropy risk
    'entropy_risk': np.zeros(n_safe),

    'is_phishing': 0
})

print(f"Realistic safe samples: {len(safe_features)}")

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