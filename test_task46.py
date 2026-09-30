r"""
TASK 4.6 — Safety Guidance & Official India Reporting Validation Suite
Tests get_safety_guidance(), get_official_reporting_info(), Sender ID guidance,
wording restrictions, and integration across all risk states.
Run with: .venv\Scripts\python test_task46.py
"""
import sys, os, warnings, unittest.mock as mock
sys.stdout.reconfigure(encoding="utf-8")

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

analyze_message            = app_mod.analyze_message
extract_urls               = app_mod.extract_urls
analyze_url                = app_mod.analyze_url
synthesize_risk            = app_mod.synthesize_risk
explain_prediction         = app_mod.explain_prediction
get_safety_guidance        = app_mod.get_safety_guidance
get_official_reporting_info = app_mod.get_official_reporting_info
model                      = app_mod.model

print("=" * 65)
print("TASK 4.6 SAFETY GUIDANCE & OFFICIAL REPORTING VALIDATION")
print("=" * 65)

# Forbidden absolute assurance phrases
FORBIDDEN_PHRASES = ["100% safe", "guaranteed safe", "definitely legitimate", "this proves it is a scam"]

# -------------------------------------------------------------------
# TEST 1: SCAM message with phishing URL
# -------------------------------------------------------------------
print("\n[TEST 1] SCAM message guidance")
url_phish = [{
    "url": "http://evil-bank.com",
    "exit_code": 2,
    "verdict": "PHISHING",
    "risk_score": 15.0,
    "signals": [],
    "error": None
}]
t3_scam = {"prediction": "SPAM", "confidence": 92.0, "risk_level": "HIGH", "indicators": ["Financial language: bank"]}
syn_scam = synthesize_risk(t3_scam, url_phish, nnz=8)
guid_scam = get_safety_guidance(syn_scam["state"], t3_scam, url_phish)

print(f"  Overall state: {syn_scam['state']}")
print(f"  Actions count: {len(guid_scam['actions'])}")
for a in guid_scam["actions"]:
    print(f"    - {a[:75]}...")
assert syn_scam["state"] == "SCAM"
assert guid_scam["alert_type"] == "error"
assert any("Do NOT click" in a for a in guid_scam["actions"])
assert any("1930" in a for a in guid_scam["actions"])
assert any("cybercrime.gov.in" in a for a in guid_scam["actions"])
assert any("Chakshu" in a for a in guid_scam["actions"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 2: SPAM message without URL
# -------------------------------------------------------------------
print("\n[TEST 2] SPAM message guidance")
t3_spam = {"prediction": "SPAM", "confidence": 91.0, "risk_level": "HIGH", "indicators": ["Prize or reward language: won"]}
syn_spam = synthesize_risk(t3_spam, [], nnz=10)
guid_spam = get_safety_guidance(syn_spam["state"], t3_spam, [])

print(f"  Overall state: {syn_spam['state']}")
for a in guid_spam["actions"]:
    print(f"    - {a[:75]}...")
assert syn_spam["state"] == "SPAM"
assert guid_spam["alert_type"] == "warning"
assert any("1909" in a for a in guid_spam["actions"])
assert any("DND" in a for a in guid_spam["actions"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 3: UNCERTAIN low-confidence message
# -------------------------------------------------------------------
print("\n[TEST 3] UNCERTAIN low-confidence message guidance")
t3_unc = {"prediction": "NOT SPAM", "confidence": 64.0, "risk_level": "MEDIUM", "indicators": []}
syn_unc = synthesize_risk(t3_unc, [], nnz=5)
guid_unc = get_safety_guidance(syn_unc["state"], t3_unc, [])

print(f"  Overall state: {syn_unc['state']}")
for a in guid_unc["actions"]:
    print(f"    - {a[:75]}...")
assert syn_unc["state"] == "UNCERTAIN"
assert any("Do not assume the message is safe" in a for a in guid_unc["actions"])
assert any("Verify the sender independently" in a for a in guid_unc["actions"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 4: OOV / Hinglish message guidance
# -------------------------------------------------------------------
print("\n[TEST 4] OOV Hinglish message guidance")
t3_oov = analyze_message("Bhai jaldi paisa bhej de gpay pe")
syn_oov = synthesize_risk(t3_oov, [], nnz=0)
guid_oov = get_safety_guidance(syn_oov["state"], t3_oov, [])

print(f"  Overall state: {syn_oov['state']}")
assert syn_oov["state"] == "UNCERTAIN"
assert any("Do not assume the message is safe" in a for a in guid_oov["actions"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 5: NO THREAT DETECTED normal message guidance
# -------------------------------------------------------------------
print("\n[TEST 5] NO THREAT DETECTED normal message guidance")
t3_ham = {"prediction": "NOT SPAM", "confidence": 95.0, "risk_level": "LOW", "indicators": []}
syn_ham = synthesize_risk(t3_ham, [], nnz=6)
guid_ham = get_safety_guidance(syn_ham["state"], t3_ham, [])

print(f"  Overall state: {syn_ham['state']}")
for a in guid_ham["actions"]:
    print(f"    - {a[:75]}...")
assert syn_ham["state"] == "NO THREAT DETECTED"
assert guid_ham["alert_type"] == "success"
assert any("No strong threat indicators detected" in a for a in guid_ham["actions"])
assert any("Never disclose OTPs" in a for a in guid_ham["actions"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 6: Verify wording restrictions (no false guarantees)
# -------------------------------------------------------------------
print("\n[TEST 6] Wording restrictions audit")
all_guidance_text = " ".join(
    " ".join(g["actions"])
    for g in [guid_scam, guid_spam, guid_unc, guid_ham]
).lower()

for forbidden in FORBIDDEN_PHRASES:
    assert forbidden not in all_guidance_text, f"Found forbidden phrase '{forbidden}' in guidance!"
print("  Zero forbidden absolute assurance phrases found [PASS]")
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 7: Verify official reporting information & URLs
# -------------------------------------------------------------------
print("\n[TEST 7] Official reporting channels verification")
reports = get_official_reporting_info()
assert len(reports) == 4

agencies = [r["agency"] for r in reports]
assert "Department of Telecommunications (DoT)" in agencies
assert "Telecom Regulatory Authority of India (TRAI)" in agencies
assert "Ministry of Home Affairs (MHA) / I4C" in agencies

urls = [r["url"] for r in reports]
assert "https://www.sancharsaathi.gov.in/sfc/" in urls
assert "https://smsheader.trai.gov.in" in urls
assert "https://www.trai.gov.in" in urls
assert "https://cybercrime.gov.in" in urls

for r in reports:
    print(f"  Verified: {r['agency']} -> {r['portal']} ({r['url']})")
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 8: Full regression across Task 3, 4.3, 4.4, 4.5
# -------------------------------------------------------------------
print("\n[TEST 8] Comprehensive Pipeline Regression")
test_sms = "URGENT: Your account has been suspended. Visit http://suspicious-login.update-paypal.com to verify."
t3_reg = analyze_message(test_sms)
urls_reg = extract_urls(test_sms)
ur_reg = [analyze_url(urls_reg[0])]
nnz_reg = model.named_steps["tfidf"].transform([test_sms]).nnz
syn_reg = synthesize_risk(t3_reg, ur_reg, nnz=nnz_reg)
exp_reg = explain_prediction(test_sms)
guid_reg = get_safety_guidance(syn_reg["state"], t3_reg, ur_reg)

print(f"  SMS: {test_sms}")
print(f"  Task 3 Prediction: {t3_reg['prediction']} ({t3_reg['confidence']:.1f}%)")
print(f"  URL Verdict: {ur_reg[0]['verdict']} (exit code {ur_reg[0]['exit_code']})")
print(f"  Synthesized State: {syn_reg['state']}")
print(f"  Explainability top terms: {[f['token'] for f in exp_reg['spam_features'][:3]]}")
print(f"  Guidance alert type: {guid_reg['alert_type']}")

assert ur_reg[0]["exit_code"] == 1  # SUSPICIOUS
assert syn_reg["state"] in ("SCAM", "UNCERTAIN")
assert len(guid_reg["actions"]) >= 4
print("  RESULT: PASS")

print("\n" + "=" * 65)
print("ALL TASK 4.6 TESTS PASSED")
print("=" * 65)
