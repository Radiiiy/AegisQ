import pickle
import matplotlib.pyplot as plt
import pandas as pd

# 1. Load your high-accuracy model
print("--- AEGISQ: XAI AUDIT COMMENCING ---")
with open('aegis_url_model_v2.pkl', 'rb') as f:
    model = pickle.load(f)

# 2. Define the features we taught the AI
feature_names = [
    'url_length', 'digit_ratio', 'entropy', 'count_dots', 
    'count_hyphens', 'count_at', 'is_https', 'suspicious_tld', 'keyword_count'
]

# 3. Extract Feature Importance (The 'X' in XAI)
importances = model.feature_importances_
feat_importances = pd.Series(importances, index=feature_names)

# 4. Generate the Explainability Plot
plt.figure(figsize=(10, 6))
feat_importances.sort_values().plot(kind='barh', color='#0078d4')
plt.title('Explainable AI (XAI): URL Feature Importance')
plt.xlabel('Impact on Security Verdict')
plt.ylabel('Analysis Feature')
plt.tight_layout()

# 5. Save and Show
plt.savefig('xai_url_explanation.png')
print("✅ XAI Audit Complete. View your results in 'xai_url_explanation.png'")
plt.show()