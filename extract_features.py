import pandas as pd
import tldextract
import re

print("--- AEGISQ: FINALIZING PHASE 1 (Feature Extraction) ---")

def extract_url_features(url):
    features = {}
    url = str(url)
    
    # 1. Basic length (Phishing URLs are often very long)
    features['url_length'] = len(url)
    
    # 2. Count special characters scammers use to hide links
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_question'] = url.count('?')
    
    # 3. Security check (is it https or just http?)
    features['is_https'] = 1 if url.startswith('https') else 0
    
    # 4. Check for 'suspicious' words often used in Sri Lankan scams
    keywords = ['login', 'verify', 'secure', 'update', 'banking', 'lanka', 'gift', 'reward']
    features['keyword_count'] = sum(1 for word in keywords if word in url.lower())
    
    return features

# Load the clean phishing data you just downloaded
print("Step 1: Reading phishing_urls_clean.csv...")
df = pd.read_csv("phishing_urls_clean.csv")

# We will process the first 1000 links to keep it fast for now
print("Step 2: Turning URLs into numbers...")
feature_list = []
for url in df['url'].head(1000):
    feature_list.append(extract_url_features(url))

# Save the new numerical dataset
feature_df = pd.DataFrame(feature_list)
feature_df.to_csv("url_features_numeric.csv", index=False)

print("--- SUCCESS: Phase 1 is officially COMPLETE! ---")
print("Check your sidebar for 'url_features_numeric.csv'")