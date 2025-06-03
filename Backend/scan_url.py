import pandas as pd
import requests
import time
import random

# Configuration
CSV_FILE = "D:\\Phishing Detection\\Backend\\phishing_site_urls.csv"  # Replace with your CSV file name
API_URL = "http://localhost:8000/scan"
OUTPUT_EXCEL = "results.xlsx"

# Limits
MAX_REQUESTS_PER_DAY = 3    
REQUESTS_PER_MINUTE = 3
DELAY_BETWEEN_REQUESTS = 60 / REQUESTS_PER_MINUTE

# Load and sample URLs
df = pd.read_csv(CSV_FILE)
urls = df.iloc[:, 0].dropna().tolist()  # Assume URLs are in the first column
random.shuffle(urls)
urls = urls[:MAX_REQUESTS_PER_DAY]

# Output list
results = []

# Run API calls
for count, url in enumerate(urls, 1):
    try:
        print(f"[{count}/{MAX_REQUESTS_PER_DAY}] Scanning: {url}")
        response = requests.post(API_URL, json={"url": url}, timeout=60)
        data = response.json()

        risk_info = data.get("risk_assessment", {})
        risk_score = risk_info.get("risk_score", "N/A")
        risk_level = risk_info.get("risk_level", "N/A")

        results.append({
            "URL": url,
            "Risk Score": risk_score,
            "Risk Level": risk_level
        })

    except Exception as e:
        print(f"❌ Error scanning {url}: {e}")
        results.append({
            "URL": url,
            "Risk Score": "Error",
            "Risk Level": "Error"
        })

    if count < MAX_REQUESTS_PER_DAY:
        print(f"⏳ Waiting {int(DELAY_BETWEEN_REQUESTS)} seconds before next request...")
        time.sleep(DELAY_BETWEEN_REQUESTS)

# Save to Excel
results_df = pd.DataFrame(results)
results_df.to_excel(OUTPUT_EXCEL, index=False)
print(f"\n✅ Scan complete. Results saved to: {OUTPUT_EXCEL}")
