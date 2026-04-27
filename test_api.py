import requests

# The address of your laptop's local server (FastAPI)
url = "http://127.0.0.1:8000/scan"

# Pick an image from your folder to test
image_path = "dataset/clean/qr_v3_0.png"

print(f"--- AEGISQ: TESTING DUAL-LAYER API ---")
print(f"Sending image: {image_path} to server...")

try:
    with open(image_path, "rb") as img:
        files = {"file": img}
        response = requests.post(url, files=files)
    
    if response.status_code == 200:
        result = response.json()
        print("\n=== AEGISQ DUAL-LAYER REPORT ===")
        print(f"Overall Status : {result['overall_status']}")
        print(f"System Message : {result['message']}")
        print(f"Scanned URL    : {result['scanned_url']}\n")
        
        v_layer = result['vision_layer']
        print(f"[Layer 1] Physical Surface : {v_layer['result']} (Confidence: {v_layer['confidence']})")
        
        u_layer = result['url_layer']
        print(f"[Layer 2] Digital Link     : {u_layer['result']} (Confidence: {u_layer['confidence']})")
        
        # Show SHAP explanation if available
        if u_layer.get('explanation'):
            print(f"\n[SHAP Explanation]")
            print(f"Summary: {u_layer['explanation']['summary']}")
            print(f"Top Risk Factors:")
            for factor in u_layer['explanation']['risk_factors']:
                print(f"  - {factor['reason']} [{factor['impact_level']}]")
        
        print("================================\n")
    
    else:
        print(f"Error: Server returned status code {response.status_code}")
        print(f"Server Details: {response.text}")

except FileNotFoundError:
    print(f"Error: Could not find '{image_path}'. Check your 'image_path' variable.")
except Exception as e:
    print(f"An error occurred: {e}")