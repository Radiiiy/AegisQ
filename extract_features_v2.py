import pandas as pd
import tldextract
import re
from scipy.stats import entropy
from collections import Counter

print("--- AEGISQ: ADVANCED FEATURE EXTRACTION (v2) ---")

def calculate_entropy(url):
    prob = [n/len(url) for n in Counter(url).values()]
    return entropy(prob, base=2)

def extract_advanced_features(url):
    url = str(url)
    features = {}
    
    # 1. Structural Features
    features['url_length'] = len(url)
    features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url)
    features['entropy'] = calculate_entropy(url)
    
    # 2. Character Counts
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    
    # 3. Security & Domain Features
    features['is_https'] = 1 if url.startswith('https') else 0
    
    # Check for suspicious TLDs (Common in phishing)
    ext = tldextract.extract(url)
    suspicious_tlds = ['zip', 'top', 'xyz', 'work', 'bid', 'click']
    features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0
    
    # 4. Keyword Intensity
    keywords = ['login', 'verify', 'secure', 'update', 'banking', 'lanka', 'gift', 'reward']
    features['keyword_count'] = sum(1 for word in keywords if word in url.lower())

    # 5. Sinhala/Tamil Localization Detection
    sinhala_tamil_unicode = any(
        '\u0D80' <= char <= '\u0DFF' or '\u0B80' <= char <= '\u0BFF'
        for char in url
    )

    transliterated_keywords = [
        'ginuma', 'tahauru', 'bank seva', 'ganum', 'within',
        'ithiripas', 'palamu', 'anuthura', 'sampurna',
        'kanakku', 'saripaaru', 'vangki', 'payam', 'pudhuppi',
        'uruthipaduthu', 'seluththu', 'vagaiyara',
        'prize winner', 'congratulations winner', 'claim reward',
        'account suspended', 'urgent action', 'immediate verify'
    ]

    features['sinhala_tamil_keywords'] = (
        1 if sinhala_tamil_unicode else 0
    ) + sum(1 for word in transliterated_keywords if word in url.lower())

    return features

# Process the data
print("Step 1: Reading clean phishing data...")
df = pd.read_csv("phishing_urls_clean.csv")

print("Step 2: Extracting Advanced numerical features (v2)...")
feature_list = [extract_advanced_features(url) for url in df['url']]

# Save the new numerical dataset
feature_df = pd.DataFrame(feature_list)
feature_df.to_csv("url_features_numeric_v2.csv", index=False)

print("--- SUCCESS: Advanced features saved to url_features_numeric_v2.csv ---")