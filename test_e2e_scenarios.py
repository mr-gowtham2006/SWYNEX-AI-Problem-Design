"""
TASK 4.7 — End-to-End Scenario Verification Script
Tests the 9 representative scenarios against the full pipeline:
A. Normal message, no URL
B. Obvious spam message
C. Phishing URL
D. Suspicious URL + suspicious SMS evidence
E. Suspicious URL + benign SMS
F. OOV / Hinglish message
G. Low-confidence NOT SPAM
H. URL analysis failure/unavailable case
I. Empty input
"""
import sys, os, unittest.mock as mock

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "task-3"))

st_mock = mock.MagicMock()
st_mock.button.return_value = False
st_mock.text_area.return_value = ""
st_mock.text_input.return_value = ""
sys.modules["streamlit"] = st_mock

import importlib.util
spec = importlib.util.spec_from_file_location("app", os.path.join(BASE, "app.py"))
app_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_mod)

analyze_message = app_mod.analyze_message
extract_urls    = app_mod.extract_urls
analyze_url     = app_mod.analyze_url
synthesize_risk = app_mod.synthesize_risk
model           = app_mod.model

def run_case(name, text, override_urls=None):
    t3 = analyze_message(text)
    if "error" in t3:
        nnz = 0
        urls = []
        ur = []
    else:
        nnz = model.named_steps["tfidf"].transform([text]).nnz
        urls = extract_urls(text)
        ur = override_urls if override_urls is not None else [analyze_url(u) for u in urls]
    syn = synthesize_risk(t3, ur, nnz=nnz)
    state = syn["state"]
    rule = syn.get("rule", "N/A")
    print(f"[{name}] -> State: {state} (Rule: {rule})")
    return state

print("=" * 65)
print("TASK 4.7 END-TO-END SCENARIO VERIFICATION")
print("=" * 65)

# A. Normal message, no URL -> NO THREAT DETECTED
s_a = run_case("A: Normal message, no URL", "Hey, are we still meeting for lunch at 12?")
assert s_a == "NO THREAT DETECTED"

# B. Obvious spam message -> SPAM
s_b = run_case("B: Obvious spam message", "URGENT! You have won a 1 week FREE membership in our $100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010")
assert s_b == "SPAM"

# C. Phishing URL -> SCAM
s_c = run_case("C: Phishing URL", "Check this: https://example.com", override_urls=[{"url": "https://example.com", "exit_code": 2, "verdict": "PHISHING", "error": None}])
assert s_c == "SCAM"

# D. Suspicious URL + suspicious SMS evidence -> SCAM
s_d = run_case("D: Suspicious URL + suspicious SMS", "URGENT: Your account suspended. Visit http://suspicious-login.update-paypal.com")
assert s_d == "SCAM"

# E. Suspicious URL + benign SMS -> UNCERTAIN
s_e = run_case("E: Suspicious URL + benign SMS", "Hey lunch at 12 at http://suspicious-login.update-paypal.com")
assert s_e == "UNCERTAIN"

# F. OOV / Hinglish message -> UNCERTAIN
s_f = run_case("F: OOV / Hinglish message", "Bhai jaldi paisa bhej de gpay pe")
assert s_f == "UNCERTAIN"

# G. Low-confidence NOT SPAM -> UNCERTAIN
s_g = run_case("G: Low-confidence NOT SPAM", "Security Alert: A new login was detected on your account from a new device.")
assert s_g == "UNCERTAIN"

# H. URL analysis failure/unavailable case -> UNCERTAIN
s_h = run_case("H: URL analysis failure", "Visit https://example.com", override_urls=[{"url": "https://example.com", "exit_code": -1, "verdict": "UNAVAILABLE", "error": "not found"}])
assert s_h == "UNCERTAIN"

# I. Empty input -> UNCERTAIN (error handled gracefully)
s_i = run_case("I: Empty input", "   ")
assert s_i == "UNCERTAIN"

print("=" * 65)
print("ALL 9 CORE SCENARIOS VERIFIED SUCCESSFULLY!")
print("=" * 65)
