#!/usr/bin/env python3
import requests
import json

email = "testuser_live_1@example.com"
password = "TestPass123!"
full_name = "Test User Live"

payload = {
    "full_name": full_name,
    "email": email,
    "password": password
}

url = "https://tii-web.onrender.com/register"
headers = {"Content-Type": "application/json"}

try:
    response = requests.post(url, json=payload, headers=headers)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response:\n{json.dumps(response.json(), indent=2)}")
    
    # Check if OTP is in response
    if "otp" in response.json():
        otp = response.json()["otp"]
        print(f"\n✅ DEBUG OTP FOUND: {otp}")
    else:
        print("\n❌ No OTP in response (production mode or error)")
except Exception as e:
    print(f"Error: {e}")
