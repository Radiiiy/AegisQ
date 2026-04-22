import pandas as pd
import xgboost as xgb
import numpy as np
import pickle

print("--- AEGISQ: FORGING THE FINAL URL BRAIN ---")

# 1. Generate 2000 Realistic SAFE URLs
safe_data = pd.DataFrame({
    'url_length': np.random.randint(20, 75, 2000),      # Normal lengths (like Wikipedia)
    'digit_ratio': np.random.uniform(0.0, 0.1, 2000),   # Very few random numbers
    'entropy': np.random.uniform(3.5, 4.5, 2000),       # Standard English text randomness
    'count_dots': np.random.randint(1, 4, 2000),        # 1 to 3 dots (www.site.com)
    'count_hyphens': np.random.randint(0, 2, 2000),
    'count_at': 0,                                      # Safe sites NEVER use @ in URLs
    'is_https': 1,                                      # Safe sites use HTTPS
    'suspicious_tld': 0,                                # No weird .xyz or .tk domains
    'keyword_count': np.random.randint(0, 2, 2000),     # Occasionally use words like 'secure'
    'is_phishing': 0                                    # LABEL: 0 = SAFE
})

# 2. Generate 2000 Realistic PHISHING URLs
phish_data = pd.DataFrame({
    'url_length': np.random.randint(30, 150, 2000),     
    'digit_ratio': np.random.uniform(0.0, 0.5, 2000),   # FIX: Hackers can use 0 numbers!
    'entropy': np.random.uniform(3.5, 6.0, 2000),       
    'count_dots': np.random.randint(1, 8, 2000),        # FIX: Hackers can use just 1 dot!
    'count_hyphens': np.random.randint(1, 5, 2000),
    'count_at': np.random.randint(0, 2, 2000),          
    'is_https': np.random.randint(0, 2, 2000),          
    'suspicious_tld': np.random.randint(0, 2, 2000),    
    'keyword_count': np.random.randint(1, 5, 2000),     # 1 to 4 keywords
    'is_phishing': 1                                    # LABEL: 1 = MALICIOUS
})

# 3. FORCE THE EXACT COLUMN ORDER (Must match main.py perfectly!)
feature_columns = [
    'url_length', 'digit_ratio', 'entropy', 'count_dots', 
    'count_hyphens', 'count_at', 'is_https', 'suspicious_tld', 'keyword_count'
]

# Combine the data
data = pd.concat([safe_data, phish_data], ignore_index=True)

# Separate features (X) and labels (y)
X = data[feature_columns] 
y = data['is_phishing']

print("Training XGBoost AI...")
# 4. Train the Model
model = xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1)
model.fit(X, y)

# 5. Save the uncorrupted brain
with open("aegis_url_model_v2.pkl", "wb") as f:
    pickle.dump(model, f)
    
print("--- SUCCESS: Aegis URL Brain is perfectly aligned! ---")