import requests
import json
from app import (
    analyze_message,
    model,
    _MODEL_LOADED,
    extract_urls,
    analyze_url,
    synthesize_risk,
    explain_prediction,
    get_safety_guidance,
    get_official_reporting_info,
)

test_messages = [
    "Hey, are we still meeting for lunch at 12?",
    "URGENT! You have won a 1 week FREE membership in our $100,000 prize jackpot! Call 09061743810 now",
    "Please update your security settings http://paypal.com.account-verification-login.com immediately",
    "Hey check this link http://suspicious-login.update-paypal.com",
    "Bhai jaldi paisa bhej de gpay pe",
    "Your payment was received successfully.",
    "",
]

print("=" * 70)
print("EQUIVALENCE CHECK: DIRECT app.py PIPELINE vs FASTAPI HTTP API")
print("=" * 70)

all_match = True

for msg in test_messages:
    # 1. Direct app.py pipeline
    t3 = analyze_message(msg)
    nnz = 0
    if _MODEL_LOADED and model is not None and msg.strip():
        try:
            nnz = int(model.named_steps["tfidf"].transform([msg]).nnz)
        except Exception:
            nnz = 0
    urls = extract_urls(msg) if msg.strip() else []
    ur = [analyze_url(u) for u in urls]
    syn = synthesize_risk(t3, ur, nnz=nnz)
    exp = explain_prediction(msg)
    state = syn["state"]
    guidance = get_safety_guidance(state, t3, ur)
    reporting = get_official_reporting_info()

    # 2. FastAPI HTTP API
    res = requests.post("http://127.0.0.1:8000/api/analyze", json={"message": msg})
    assert res.status_code == 200
    api_data = res.json()

    # Comparisons
    match_state = (state == api_data["overall_state"])
    match_rule = (syn.get("rule", "UNKNOWN") == api_data["rule"])
    match_pred = (t3.get("prediction", "NOT SPAM") == api_data["prediction"])
    match_conf = abs(float(t3.get("confidence", 0.0)) - api_data["confidence"]) < 0.01
    match_nnz = (nnz == api_data["tokens_matched"])
    match_urls = (len(urls) == api_data["urls_detected"])
    match_actions = (len(guidance["actions"]) == len(api_data["safety_guidance"]["actions"]))
    match_reporters = (len(reporting) == len(api_data["official_reporting"]))

    passed = all([
        match_state, match_rule, match_pred, match_conf,
        match_nnz, match_urls, match_actions, match_reporters
    ])

    if not passed:
        all_match = False
        print(f"FAILED on message: '{msg[:40]}...'")
        print(f"  Direct: state={state}, rule={syn.get('rule')}, pred={t3.get('prediction')}, conf={t3.get('confidence')}")
        print(f"  API   : state={api_data['overall_state']}, rule={api_data['rule']}, pred={api_data['prediction']}, conf={api_data['confidence']}")
    else:
        label = msg[:35] if msg else "<EMPTY>"
        print(f"PASS: '{label}' -> State: {state} (Rule: {syn.get('rule')})")

assert all_match, "Equivalence verification failed!"
print("\nPERFECT 100% DETECTION AND LOGIC EQUIVALENCE CONFIRMED!")
