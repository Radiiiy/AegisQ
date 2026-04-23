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

    # Raw entropy calculation
    from collections import Counter
    from scipy.stats import entropy as scipy_entropy
    prob = [n/len(url) for n in Counter(url).values()]
    raw_entropy = scipy_entropy(prob, base=2)
    features['entropy'] = raw_entropy

    # 2. Character Counts
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')

    # 3. Security & Domain Features
    features['is_https'] = 1 if url.startswith('https') else 0

    ext = tldextract.extract(url)
    domain_name = ext.domain.lower()

    suspicious_tlds = ['zip', 'top', 'xyz', 'work', 'bid', 'click']
    features['suspicious_tld'] = 1 if ext.suffix in suspicious_tlds else 0

    # NEW - Safe TLD check
    safe_tlds = ['com', 'org', 'net', 'edu', 'gov', 'ac', 'lk',
                 'uk', 'au', 'io', 'google', 'youtube', 'microsoft']
    features['safe_tld'] = 1 if ext.suffix in safe_tlds else 0

    # NEW - Trusted domain check
    trusted_domains = [
        'google', 'youtube', 'facebook', 'instagram', 'twitter',
        'microsoft', 'apple', 'amazon', 'netflix', 'spotify',
        'github', 'stackoverflow', 'wikipedia', 'reddit', 'linkedin',
        'whatsapp', 'telegram', 'tiktok', 'snapchat', 'pinterest',
        'boc', 'sampath', 'combank', 'hnb', 'nsbm', 'cmb', 'seylan',
        'dfcc', 'nations', 'peoples', 'lankapay', 'lankaqr', 'cbsl',
        'gov', 'edu', 'ac', 'university', 'bank'
    ]
    # Check domain name AND suffix (handles share.google, maps.google etc)
    features['is_trusted_domain'] = 1 if (
        any(td in domain_name for td in trusted_domains) or
        any(td in ext.suffix for td in trusted_domains)
    ) else 0

    # 4. Keyword Intensity
    keywords = ['login', 'verify', 'secure', 'update', 'banking',
                'lanka', 'gift', 'reward']
    features['keyword_count'] = sum(
        1 for word in keywords if word in url.lower()
    )

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

    # 6. NEW - Composite Entropy Risk
    # High entropy is only suspicious when COMBINED with other bad signals
    # Legitimate URLs can have high entropy tokens (Google share links etc)
    features['entropy_risk'] = (
        1 if (
            raw_entropy > 4.5
            and features['suspicious_tld'] == 1
            and features['is_https'] == 0
            and features['is_trusted_domain'] == 0
        ) else 0
    )

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