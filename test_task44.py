r"""
TASK 4.4 — Risk Synthesis & Uncertainty Validation Suite
Tests synthesize_risk() logic, integration with Task 3 and Task 4.3,
and all 12+ required test scenarios directly.
Run with: .venv\Scripts\python test_task44.py
"""
import sys, os, warnings, unittest.mock as mock

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "task-3"))

# Stub streamlit for module import
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

print("=" * 65)
print("TASK 4.4 RISK SYNTHESIS VALIDATION SUITE")
print("=" * 65)

# -------------------------------------------------------------------
# TEST 1: Normal ham, no URL -> NO THREAT DETECTED
# -------------------------------------------------------------------
print("\n[TEST 1] Normal ham, no URL")
msg1 = "Hey, are we still meeting for lunch at 12?"
t3_1 = analyze_message(msg1)
urls1 = extract_urls(msg1)
nnz1 = model.named_steps["tfidf"].transform([msg1]).nnz
syn1 = synthesize_risk(t3_1, [], nnz=nnz1)
print(f"  Prediction: {t3_1['prediction']}, Conf: {t3_1['confidence']}%, nnz: {nnz1}")
print(f"  Overall state: {syn1['state']} (Rule: {syn1['rule']})")
print(f"  Reason: {syn1['reason']}")
assert syn1["state"] == "NO THREAT DETECTED"
assert t3_1["prediction"] == "NOT SPAM"
assert t3_1["risk_level"] == "LOW"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 2: Obvious spam, no URL -> SPAM
# -------------------------------------------------------------------
print("\n[TEST 2] Obvious spam, no URL")
msg2 = "URGENT! You have won a 1 week FREE membership in our $100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010"
t3_2 = analyze_message(msg2)
urls2 = extract_urls(msg2)
nnz2 = model.named_steps["tfidf"].transform([msg2]).nnz
syn2 = synthesize_risk(t3_2, [], nnz=nnz2)
print(f"  Prediction: {t3_2['prediction']}, Conf: {t3_2['confidence']}%, nnz: {nnz2}")
print(f"  Overall state: {syn2['state']} (Rule: {syn2['rule']})")
print(f"  Reason: {syn2['reason']}")
assert syn2["state"] == "SPAM"
assert t3_2["prediction"] == "SPAM"
assert t3_2["risk_level"] == "HIGH"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 3: NOT SPAM with confidence < 70% -> UNCERTAIN
# -------------------------------------------------------------------
print("\n[TEST 3] NOT SPAM with confidence < 70%")
msg3 = "Security Alert: A new login was detected on your account from a new device."
t3_3 = analyze_message(msg3)
nnz3 = model.named_steps["tfidf"].transform([msg3]).nnz
syn3 = synthesize_risk(t3_3, [], nnz=nnz3)
print(f"  Prediction: {t3_3['prediction']}, Conf: {t3_3['confidence']}%, nnz: {nnz3}")
print(f"  Overall state: {syn3['state']} (Rule: {syn3['rule']})")
print(f"  Reason: {syn3['reason']}")
assert t3_3["confidence"] < 70.0
assert syn3["state"] == "UNCERTAIN"
assert syn3["rule"] == "LOW_CONFIDENCE_HAM"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 4: OOV / Zero TF-IDF (nnz == 0) -> UNCERTAIN
# -------------------------------------------------------------------
print("\n[TEST 4] Pure OOV Hinglish message (nnz == 0)")
msg4 = "Bhai jaldi paisa bhej de gpay pe"
t3_4 = analyze_message(msg4)
nnz4 = model.named_steps["tfidf"].transform([msg4]).nnz
syn4 = synthesize_risk(t3_4, [], nnz=nnz4)
print(f"  Task 3 raw: {t3_4['prediction']} (Conf: {t3_4['confidence']}%), nnz: {nnz4}")
print(f"  Overall state: {syn4['state']} (Rule: {syn4['rule']})")
print(f"  Reason: {syn4['reason']}")
assert nnz4 == 0
assert syn4["state"] == "UNCERTAIN"
assert syn4["rule"] == "OUT_OF_VOCABULARY"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 5: Phishing URL -> SCAM (overrides benign message)
# -------------------------------------------------------------------
print("\n[TEST 5] Phishing URL (exit 2)")
t3_5 = {"prediction": "NOT SPAM", "confidence": 92.0, "risk_level": "LOW", "indicators": []}
url_phish = [{
    "url": "http://evil-apple-id.verify.com",
    "exit_code": 2,
    "verdict": "PHISHING",
    "risk_score": 15.0,
    "signals": [{"severity": "CRITICAL", "label": "Phishing feed"}],
    "error": None
}]
syn5 = synthesize_risk(t3_5, url_phish, nnz=5)
print(f"  Overall state: {syn5['state']} (Rule: {syn5['rule']})")
print(f"  Reason: {syn5['reason']}")
assert syn5["state"] == "SCAM"
assert syn5["rule"] == "PHISHING_URL"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 6: Suspicious URL + Suspicious SMS evidence -> SCAM
# -------------------------------------------------------------------
print("\n[TEST 6] Suspicious URL + Suspicious SMS evidence (indicators present)")
t3_6 = {
    "prediction": "NOT SPAM",
    "confidence": 65.0,
    "risk_level": "MEDIUM",
    "indicators": ["Urgency language: immediately", "Financial language: bank"]
}
url_susp = [{
    "url": "http://suspicious-login.update-paypal.com",
    "exit_code": 1,
    "verdict": "SUSPICIOUS",
    "risk_score": 5.6,
    "signals": [{"severity": "HIGH", "label": "Brand impersonation"}],
    "error": None
}]
syn6 = synthesize_risk(t3_6, url_susp, nnz=8)
print(f"  Overall state: {syn6['state']} (Rule: {syn6['rule']})")
print(f"  Reason: {syn6['reason']}")
assert syn6["state"] == "SCAM"
assert syn6["rule"] == "SUSPICIOUS_URL_WITH_SMS_INDICATORS"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 7: Suspicious URL + Normal SMS -> UNCERTAIN (conflicting evidence)
# -------------------------------------------------------------------
print("\n[TEST 7] Suspicious URL + Normal SMS (no indicators, NOT SPAM)")
t3_7 = {
    "prediction": "NOT SPAM",
    "confidence": 95.0,
    "risk_level": "LOW",
    "indicators": []
}
syn7 = synthesize_risk(t3_7, url_susp, nnz=5)
print(f"  Overall state: {syn7['state']} (Rule: {syn7['rule']})")
print(f"  Reason: {syn7['reason']}")
assert syn7["state"] == "UNCERTAIN"
assert syn7["rule"] == "SUSPICIOUS_URL_CONFLICT"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 8: Safe URL + Normal SMS -> NO THREAT DETECTED
# -------------------------------------------------------------------
print("\n[TEST 8] Safe URL + Normal SMS")
t3_8 = {
    "prediction": "NOT SPAM",
    "confidence": 94.0,
    "risk_level": "LOW",
    "indicators": []
}
url_safe = [{
    "url": "https://example.com/order/123",
    "exit_code": 0,
    "verdict": "SAFE",
    "risk_score": 0.0,
    "signals": [],
    "error": None
}]
syn8 = synthesize_risk(t3_8, url_safe, nnz=6)
print(f"  Overall state: {syn8['state']} (Rule: {syn8['rule']})")
print(f"  Reason: {syn8['reason']}")
assert syn8["state"] == "NO THREAT DETECTED"
assert syn8["rule"] == "NO_THREAT"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 9: URL analysis unavailable -> UNCERTAIN
# -------------------------------------------------------------------
print("\n[TEST 9] URL analysis unavailable (exit_code -1)")
t3_9 = {"prediction": "NOT SPAM", "confidence": 90.0, "risk_level": "LOW", "indicators": []}
url_unavail = [{
    "url": "https://some-link.com",
    "exit_code": -1,
    "verdict": "UNAVAILABLE",
    "risk_score": None,
    "signals": [],
    "error": "barb-phish not installed"
}]
syn9 = synthesize_risk(t3_9, url_unavail, nnz=4)
print(f"  Overall state: {syn9['state']} (Rule: {syn9['rule']})")
print(f"  Reason: {syn9['reason']}")
assert syn9["state"] == "UNCERTAIN"
assert syn9["rule"] == "URL_ANALYSIS_FAILED"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 10: URL analysis timeout / error -> UNCERTAIN
# -------------------------------------------------------------------
print("\n[TEST 10] URL analysis timeout / error (exit_code -2 / 3)")
url_timeout = [{
    "url": "https://slow-link.com",
    "exit_code": -2,
    "verdict": "TIMEOUT",
    "risk_score": None,
    "signals": [],
    "error": "URL analysis timed out"
}]
syn10 = synthesize_risk(t3_9, url_timeout, nnz=4)
print(f"  Timeout state: {syn10['state']} (Rule: {syn10['rule']})")
assert syn10["state"] == "UNCERTAIN"
assert syn10["rule"] == "URL_ANALYSIS_FAILED"

url_err3 = [{
    "url": "https://error-link.com",
    "exit_code": 3,
    "verdict": "ERROR",
    "risk_score": None,
    "signals": [],
    "error": "Internal CLI error"
}]
syn10b = synthesize_risk(t3_9, url_err3, nnz=4)
print(f"  Error 3 state: {syn10b['state']} (Rule: {syn10b['rule']})")
assert syn10b["state"] == "UNCERTAIN"
assert syn10b["rule"] == "URL_ANALYSIS_FAILED"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 11: Multiple URLs with mixed results
# -------------------------------------------------------------------
print("\n[TEST 11] Multiple URLs with mixed results")
# Safe + Phishing -> SCAM
syn11_phish = synthesize_risk(t3_8, url_safe + url_phish, nnz=6)
print(f"  Safe + Phishing -> State: {syn11_phish['state']} (Rule: {syn11_phish['rule']})")
assert syn11_phish["state"] == "SCAM"

# Safe + Suspicious (normal SMS) -> UNCERTAIN
syn11_susp = synthesize_risk(t3_8, url_safe + url_susp, nnz=6)
print(f"  Safe + Suspicious -> State: {syn11_susp['state']} (Rule: {syn11_susp['rule']})")
assert syn11_susp["state"] == "UNCERTAIN"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 12: Conflicting evidence / Borderline spam -> UNCERTAIN
# -------------------------------------------------------------------
print("\n[TEST 12] Borderline SPAM (conf < 85% and < 3 indicators)")
t3_12 = {
    "prediction": "SPAM",
    "confidence": 62.0,
    "risk_level": "MEDIUM",
    "indicators": ["Promotional language: discount"]
}
syn12 = synthesize_risk(t3_12, [], nnz=6)
print(f"  Overall state: {syn12['state']} (Rule: {syn12['rule']})")
print(f"  Reason: {syn12['reason']}")
assert syn12["state"] == "UNCERTAIN"
assert syn12["rule"] == "BORDERLINE_SPAM"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 13: Full end-to-end regression check
# -------------------------------------------------------------------
print("\n[TEST 13] Full regression check on Task 3 + URL analysis")
msg_end2end = "Your account is locked. Verify at http://suspicious-login.update-paypal.com"
t3_e2e = analyze_message(msg_end2end)
urls_e2e = extract_urls(msg_end2end)
assert len(urls_e2e) == 1
ur_e2e = [analyze_url(urls_e2e[0])]
nnz_e2e = model.named_steps["tfidf"].transform([msg_end2end]).nnz
syn_e2e = synthesize_risk(t3_e2e, ur_e2e, nnz=nnz_e2e)
print(f"  Message: {msg_end2end}")
print(f"  Task 3: {t3_e2e['prediction']} ({t3_e2e['confidence']}%, {t3_e2e['risk_level']})")
print(f"  URL Verdict: {ur_e2e[0]['verdict']} (exit code {ur_e2e[0]['exit_code']})")
print(f"  Synthesized State: {syn_e2e['state']} (Rule: {syn_e2e['rule']})")
assert ur_e2e[0]["exit_code"] == 1  # SUSPICIOUS
assert syn_e2e["state"] in ("SCAM", "UNCERTAIN")
print("  RESULT: PASS")

print("\n" + "=" * 65)
print("ALL TASK 4.4 VALIDATION TESTS PASSED")
print("=" * 65)
