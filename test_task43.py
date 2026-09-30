r"""
TASK 4.3 validation script.
Tests URL extraction and barb-phish analysis directly — no Streamlit needed.
Run with: .venv\Scripts\python test_task43.py
"""
import sys, os, warnings

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "task-3"))

# Silence sklearn version warning (1.6.1 venv)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from intelligent_detector import analyze_message

# Import Task 4.3 helpers from app module without running Streamlit
# We import selectively by executing just the helper definitions
import importlib.util, types

import unittest.mock as mock
st_mock = mock.MagicMock()
st_mock.button.return_value = False
st_mock.text_area.return_value = ""
st_mock.text_input.return_value = ""
sys.modules["streamlit"] = st_mock

spec = importlib.util.spec_from_file_location("app", os.path.join(BASE, "app.py"))
app_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_mod)

extract_urls = app_mod.extract_urls
analyze_url  = app_mod.analyze_url

print("=" * 65)
print("TASK 4.3 VALIDATION")
print("=" * 65)

# -----------------------------------------------------------------------
# TEST 1: No URL
# -----------------------------------------------------------------------
print("\n[TEST 1] No URL in message")
msg = "Hey, are we still meeting for lunch at 12?"
urls = extract_urls(msg)
print(f"  Input: {repr(msg)}")
print(f"  URLs extracted: {urls}")
assert urls == [], f"Expected [], got {urls}"
# Task 3 still works
t3 = analyze_message(msg)
assert t3["prediction"] == "NOT SPAM"
print(f"  Task3 prediction: {t3['prediction']} ({t3['confidence']}%) [PASS]")
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 2: Known benign URL
# -----------------------------------------------------------------------
print("\n[TEST 2] Benign URL (https://example.com)")
msg2 = "Track your order here: https://example.com/track/12345"
urls2 = extract_urls(msg2)
print(f"  URLs extracted: {urls2}")
assert len(urls2) == 1 and "https://example.com" in urls2[0]
ur2 = analyze_url(urls2[0])
print(f"  Exit code: {ur2['exit_code']}")
print(f"  Verdict: {ur2['verdict']}")
print(f"  Risk score: {ur2['risk_score']}")
print(f"  Error: {ur2['error']}")
assert ur2["exit_code"] == 0, f"Expected exit 0, got {ur2['exit_code']}"
assert ur2["verdict"] == "SAFE"
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 3: Suspicious/phishing test URL (same one used in earlier barb verification)
# -----------------------------------------------------------------------
print("\n[TEST 3] Suspicious URL (http://suspicious-login.update-paypal.com)")
msg3 = "Your account needs verification: http://suspicious-login.update-paypal.com"
urls3 = extract_urls(msg3)
print(f"  URLs extracted: {urls3}")
assert len(urls3) == 1
ur3 = analyze_url(urls3[0])
print(f"  Exit code: {ur3['exit_code']}")
print(f"  Verdict: {ur3['verdict']}")
print(f"  Risk score: {ur3['risk_score']}")
print(f"  Signals count: {len(ur3['signals'])}")
for sig in ur3["signals"]:
    print(f"    - [{sig.get('severity')}] {sig.get('label')}: {sig.get('detail')}")
print(f"  Error: {ur3['error']}")
assert ur3["exit_code"] in (1, 2), f"Expected exit 1 or 2, got {ur3['exit_code']}"
assert ur3["verdict"] in ("SUSPICIOUS", "PHISHING")
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 4: Multiple URLs
# -----------------------------------------------------------------------
print("\n[TEST 4] Multiple URLs")
msg4 = "Check https://example.com or visit http://suspicious-login.update-paypal.com for details"
urls4 = extract_urls(msg4)
print(f"  URLs extracted: {urls4}")
assert len(urls4) == 2, f"Expected 2 URLs, got {len(urls4)}: {urls4}"
results4 = [analyze_url(u) for u in urls4]
for i, r in enumerate(results4):
    print(f"  URL {i+1}: {r['url']} -> exit={r['exit_code']}, verdict={r['verdict']}")
# First should be safe, second suspicious
assert results4[0]["exit_code"] == 0
assert results4[1]["exit_code"] in (1, 2)
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 5: Malformed/non-URL text (regex pre-filter)
# -----------------------------------------------------------------------
print("\n[TEST 5] Malformed/non-URL strings should not be extracted")
msg5 = "Call us at 1800-123-4567 or email support@bank.com for help"
urls5 = extract_urls(msg5)
print(f"  Input: {repr(msg5)}")
print(f"  URLs extracted: {urls5}")
# email addresses and phone numbers must NOT match the URL regex
assert urls5 == [], f"Expected [], got {urls5}"
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 6: barb-phish unavailable / error path
# -----------------------------------------------------------------------
print("\n[TEST 6] barb-phish unavailable (FileNotFoundError path)")
import subprocess as _sp

original_check_output = _sp.check_output
def _raise_fnf(*args, **kwargs):
    raise FileNotFoundError("barb not found")
_sp.check_output = _raise_fnf

ur6 = analyze_url("https://example.com")
_sp.check_output = original_check_output

print(f"  Exit code: {ur6['exit_code']}")
print(f"  Verdict: {ur6['verdict']}")
print(f"  Error: {ur6['error']}")
assert ur6["exit_code"] == -1
assert ur6["verdict"] == "UNAVAILABLE"
assert ur6["error"] is not None
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 6B: Timeout handling
# -----------------------------------------------------------------------
print("\n[TEST 6B] barb-phish timeout handling (TimeoutExpired path)")
def _raise_timeout(*args, **kwargs):
    raise _sp.TimeoutExpired(cmd=["barb", "analyze"], timeout=10)
_sp.check_output = _raise_timeout
ur_to = analyze_url("https://example.com")
_sp.check_output = original_check_output
print(f"  Exit code: {ur_to['exit_code']}")
print(f"  Verdict: {ur_to['verdict']}")
print(f"  Error: {ur_to['error']}")
assert ur_to["exit_code"] == -2
assert ur_to["verdict"] == "TIMEOUT"
assert "timed out" in ur_to["error"]
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 6C: Exit code 2 (PHISHING) handling with non-zero exit parsing
# -----------------------------------------------------------------------
print("\n[TEST 6C] Exit code 2 (PHISHING) parsing")
import json
phish_json = json.dumps({
    "url": "http://evil-bank-login.com",
    "signals": [{"severity": "CRITICAL", "label": "Known Phishing", "detail": "Match in phishing feed"}],
    "risk_score": 15.0,
    "verdict": "PHISHING"
})
def _raise_phish_cpe(*args, **kwargs):
    raise _sp.CalledProcessError(returncode=2, cmd=["barb", "analyze"], output=phish_json)
_sp.check_output = _raise_phish_cpe
ur_phish = analyze_url("http://evil-bank-login.com")
_sp.check_output = original_check_output
print(f"  Exit code: {ur_phish['exit_code']}")
print(f"  Verdict: {ur_phish['verdict']}")
print(f"  Risk score: {ur_phish['risk_score']}")
assert ur_phish["exit_code"] == 2
assert ur_phish["verdict"] == "PHISHING"
assert ur_phish["risk_score"] == 15.0
assert len(ur_phish["signals"]) == 1
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 6D: Exit code 3 / Error with non-JSON output
# -----------------------------------------------------------------------
print("\n[TEST 6D] Exit code 3 / Error handling with non-JSON output")
def _raise_err_cpe(*args, **kwargs):
    raise _sp.CalledProcessError(returncode=3, cmd=["barb", "analyze"], output="Internal CLI error occurred")
_sp.check_output = _raise_err_cpe
ur_err = analyze_url("http://error-trigger.com")
_sp.check_output = original_check_output
print(f"  Exit code: {ur_err['exit_code']}")
print(f"  Verdict: {ur_err['verdict']}")
print(f"  Error: {ur_err['error']}")
assert ur_err["exit_code"] == 3
assert ur_err["verdict"] == "ERROR"
assert ur_err["error"] is not None
print("  RESULT: PASS")

# -----------------------------------------------------------------------
# TEST 7: Task 3 still behaves as before (regression check)
# -----------------------------------------------------------------------
print("\n[TEST 7] Task 3 regression check")
spam_msg = "URGENT! You have won a FREE prize worth 1000! Click CLAIM"
t3s = analyze_message(spam_msg)
print(f"  Spam msg prediction: {t3s['prediction']}, conf: {t3s['confidence']}%")
assert t3s["prediction"] == "SPAM", f"Expected SPAM, got {t3s['prediction']}"
assert "indicators" in t3s
assert "risk_level" in t3s

ham_msg = "Hey, are we still meeting for lunch at 12?"
t3h = analyze_message(ham_msg)
print(f"  Ham msg prediction: {t3h['prediction']}, conf: {t3h['confidence']}%")
assert t3h["prediction"] == "NOT SPAM"
assert "indicators" in t3h
assert "risk_level" in t3h

print("  RESULT: PASS")

print("\n" + "=" * 65)
print("ALL TASK 4.3 TESTS PASSED")
print("=" * 65)
