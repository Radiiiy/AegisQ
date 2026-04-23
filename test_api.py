import requests

# The address of your laptop's local server (FastAPI)
url = "http://127.0.0.1:8000/scan"

# 1. Pick an image from your folder to test
# You can change this to a 'clean' image path later to test the other scenario!
image_path = "dataset/tampered/subtle_attack_qr.png"

print(f"--- AEGISQ: TESTING DUAL-LAYER API ---")
print(f"Sending image: {image_path} to server...")

try:
    with open(image_path, "rb") as img:
        # 2. Send the image to the /scan endpoint
        files = {"file": img}
        response = requests.post(url, files=files)
    
    # 3. Print the AI's Dual-Layer Verdict
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
        print("================================\n")
    else:
        print(f"Error: Server returned status code {response.status_code}")
        # This will print the exact error if the server crashes (e.g., missing xgboost)
        print(f"Server Details: {response.text}") 

except FileNotFoundError:
    print(f"Error: Could not find '{image_path}'. Check your 'image_path' variable.")
except Exception as e:
    print(f"An error occurred: {e}")