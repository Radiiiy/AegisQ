import requests
import pandas as pd
import os

print("--- AEGISQ: DATA ACQUISITION ---")

# The URL for PhishTank's community-verified 'online and valid' phishing data
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

def download_dataset():
    print("Step 1: Requesting data from PhishTank...")
    try:
        # We add a 'User-Agent' so PhishTank knows we are a research project
        response = requests.get(PHISHTANK_URL, headers={'User-Agent': 'AegisQ-Research-Project'})
        
        if response.status_code == 200:
            with open("phishing_links_raw.csv", "wb") as f:
                f.write(response.content)
            print("Step 2: Raw data saved to 'phishing_links_raw.csv'.")
            
            # Clean the data to keep only the URLs
            df = pd.read_csv("phishing_links_raw.csv")
            urls = df[['url']]
            urls.to_csv("phishing_urls_clean.csv", index=False)
            print(f"Step 3: Cleaned {len(urls)} URLs for training.")
        else:
            print(f"Error: PhishTank returned code {response.status_code}. Try again in 5 minutes.")
            
    except Exception as e:
        print(f"An error occurred: {e}")

download_dataset()
print("--- PHASE 1: URL COLLECTION COMPLETE ---")