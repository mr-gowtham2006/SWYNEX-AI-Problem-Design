import requests
import json

test_cases = [
    ("Normal SMS", {"message": "Hey, are we still meeting for lunch at 12?"}),
    ("Obvious Spam", {"message": "URGENT! You have won a 1 week FREE membership in our $100,000 prize jackpot! Call 09061743810 now"}),
    ("Phishing URL", {"message": "Please update your security settings http://paypal.com.account-verification-login.com immediately"}),
    ("Suspicious URL + benign SMS", {"message": "Hey check this link http://suspicious-login.update-paypal.com"}),
    ("Hinglish/OOV", {"message": "Bhai jaldi paisa bhej de gpay pe"}),
    ("Empty input", {"message": ""}),
    ("Multiple URLs", {"message": "Check our main site at https://google.com or visit http://suspicious-login.update-paypal.com for updates", "sender_id": "VK-HDFCBK"}),
]

print("=" * 70)
print("LIVE FASTAPI VERIFICATION OVER HTTP (http://127.0.0.1:8000)")
print("=" * 70)

for label, payload in test_cases:
    res = requests.post("http://127.0.0.1:8000/api/analyze", json=payload)
    assert res.status_code == 200, f"Expected 200 but got {res.status_code}"
    data = res.json()
    print(f"[{label}]")
    print(f"  HTTP Status    : {res.status_code}")
    print(f"  Overall State  : {data.get('overall_state')}")
    print(f"  Rule Triggered : {data.get('rule')}")
    print(f"  Prediction     : {data.get('prediction')} ({data.get('confidence'):.1f}%)")
    print(f"  Risk Level     : {data.get('risk_level')}")
    print(f"  URLs Detected  : {data.get('urls_detected')}")
    if data.get("sender_info"):
        print(f"  Sender Info    : {data['sender_info']['sender_id']} (Valid: {data['sender_info']['is_valid_format']})")
    print()

print("ALL LIVE HTTP CASES VERIFIED SUCCESSFULLY!")
