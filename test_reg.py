import requests
import json
import time

email = f'test_{int(time.time())}@example.com'
print(f"Testing with email: {email}")

r = requests.post(
    'https://tii-web.onrender.com/register',
    json={'full_name': 'Test User', 'email': email, 'password': 'Pass123!'},
    timeout=10
)

print(f"Status: {r.status_code}")
data = r.json()
print(json.dumps(data, indent=2))

if 'otp' in data:
    print(f"\n✅ DEBUG OTP FOUND: {data['otp']}")
else:
    print("\n❌ No OTP in response")
