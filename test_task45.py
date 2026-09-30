r"""
TASK 4.5 — Explainability Validation Suite
Tests explain_prediction(), feature contribution calculation, OOV handling,
and integration with Task 3 and Task 4.4.
Run with: .venv\Scripts\python test_task45.py
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

analyze_message    = app_mod.analyze_message
extract_urls       = app_mod.extract_urls
analyze_url        = app_mod.analyze_url
synthesize_risk    = app_mod.synthesize_risk
explain_prediction = app_mod.explain_prediction
model              = app_mod.model

print("=" * 65)
print("TASK 4.5 EXPLAINABILITY VALIDATION SUITE")
print("=" * 65)

# -------------------------------------------------------------------
# TEST 1: Normal ham message
# -------------------------------------------------------------------
print("\n[TEST 1] Normal ham message")
msg1 = "Hey, are we still meeting for lunch at 12?"
exp1 = explain_prediction(msg1)
print(f"  Input: {msg1}")
print(f"  has_features: {exp1['has_features']}, nnz: {exp1['nnz']}")
print(f"  Spam features: {[f['token'] for f in exp1['spam_features']]}")
print(f"  Ham features: {[f['token'] for f in exp1['ham_features']]}")
print(f"  Summary: {exp1['summary']}")
assert exp1["has_features"] is True
assert exp1["nnz"] > 0
# All reported tokens must be substrings of the input (case-insensitive)
for f in exp1["spam_features"] + exp1["ham_features"]:
    assert f["token"].lower() in msg1.lower(), f"Invented token {f['token']} not in {msg1}"
    if f["direction"] == "SPAM":
        assert f["contribution"] > 0
    else:
        assert f["contribution"] < 0
assert any(h["token"] in ["hey", "lunch", "meeting"] for h in exp1["ham_features"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 2: Obvious spam message
# -------------------------------------------------------------------
print("\n[TEST 2] Obvious spam message")
msg2 = "URGENT! You have won a 1 week FREE membership in our $100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010"
exp2 = explain_prediction(msg2)
print(f"  Input: {msg2[:60]}...")
print(f"  Spam features: {[(f['token'], f['contribution']) for f in exp2['spam_features']]}")
print(f"  Ham features: {[(f['token'], f['contribution']) for f in exp2['ham_features']]}")
print(f"  Summary: {exp2['summary']}")
assert exp2["has_features"] is True
assert len(exp2["spam_features"]) >= 3
# Ensure top spam tokens are present
top_spam_tokens = [f["token"] for f in exp2["spam_features"]]
assert any(tok in top_spam_tokens for tok in ["txt", "claim", "prize", "free", "urgent"])
for f in exp2["spam_features"]:
    assert f["contribution"] > 0
    assert f["direction"] == "SPAM"
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 3: Message with known spam-indicative terms
# -------------------------------------------------------------------
print("\n[TEST 3] Message with multiple known spam terms")
msg3 = "WINNER! Claim your FREE cash prize now!"
exp3 = explain_prediction(msg3)
print(f"  Input: {msg3}")
print(f"  Spam features: {[f['token'] for f in exp3['spam_features']]}")
print(f"  Summary: {exp3['summary']}")
assert exp3["has_features"] is True
assert len(exp3["spam_features"]) >= 2
assert all(f["contribution"] > 0 for f in exp3["spam_features"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 4: Message with terms that push toward NOT SPAM
# -------------------------------------------------------------------
print("\n[TEST 4] Message with terms pushing toward NOT SPAM")
msg4 = "See you at the office meeting tomorrow for lunch"
exp4 = explain_prediction(msg4)
print(f"  Input: {msg4}")
print(f"  Ham features: {[(f['token'], f['contribution']) for f in exp4['ham_features']]}")
print(f"  Summary: {exp4['summary']}")
assert exp4["has_features"] is True
assert len(exp4["ham_features"]) >= 1
assert all(f["contribution"] < 0 for f in exp4["ham_features"])
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 5: Mixed / conflicting message
# -------------------------------------------------------------------
print("\n[TEST 5] Mixed message with both spam and ham terms")
msg5 = "Urgent meeting about your free account balance tomorrow"
exp5 = explain_prediction(msg5)
print(f"  Input: {msg5}")
print(f"  Spam tokens: {[f['token'] for f in exp5['spam_features']]}")
print(f"  Ham tokens: {[f['token'] for f in exp5['ham_features']]}")
print(f"  Summary: {exp5['summary']}")
assert exp5["has_features"] is True
assert len(exp5["spam_features"]) > 0
assert len(exp5["ham_features"]) > 0
assert "Mixed evidence" in exp5["summary"] or "pushed" in exp5["summary"]
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 6: Pure OOV Hinglish message (nnz == 0)
# -------------------------------------------------------------------
print("\n[TEST 6] Pure OOV Hinglish message (nnz == 0)")
msg6 = "Bhai jaldi paisa bhej de gpay pe"
exp6 = explain_prediction(msg6)
print(f"  Input: {msg6}")
print(f"  has_features: {exp6['has_features']}")
print(f"  nnz: {exp6['nnz']}")
print(f"  Spam features: {exp6['spam_features']}")
print(f"  Ham features: {exp6['ham_features']}")
print(f"  Summary: {exp6['summary']}")
assert exp6["has_features"] is False
assert exp6["nnz"] == 0
assert exp6["spam_features"] == []
assert exp6["ham_features"] == []
assert "did not recognize any learned vocabulary" in exp6["summary"]
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 7: Empty message handling
# -------------------------------------------------------------------
print("\n[TEST 7] Empty message handling")
exp7 = explain_prediction("")
print(f"  Empty message summary: {exp7['summary']}")
assert exp7["has_features"] is False
assert exp7["nnz"] == 0

exp7_space = explain_prediction("   ")
assert exp7_space["has_features"] is False
print("  RESULT: PASS")

# -------------------------------------------------------------------
# TEST 8: Verify Task 3 indicators and Task 4.4 synthesis unchanged
# -------------------------------------------------------------------
print("\n[TEST 8] Regression: Task 3 indicators & Task 4.4 overall state")
msg8 = "URGENT! You have won a FREE prize worth 1000! Click CLAIM"
t3_8 = analyze_message(msg8)
syn8 = synthesize_risk(t3_8, [], nnz=model.named_steps["tfidf"].transform([msg8]).nnz)
exp8 = explain_prediction(msg8)
print(f"  Task 3 Prediction: {t3_8['prediction']} ({t3_8['confidence']}%)")
print(f"  Task 3 Indicators: {t3_8['indicators']}")
print(f"  Task 4.4 Overall: {syn8['state']}")
print(f"  Task 4.5 Top Spam: {[f['token'] for f in exp8['spam_features']]}")
assert t3_8["prediction"] == "SPAM"
assert len(t3_8["indicators"]) > 0
assert syn8["state"] == "SPAM"
assert len(exp8["spam_features"]) > 0
print("  RESULT: PASS")

print("\n" + "=" * 65)
print("ALL TASK 4.5 EXPLAINABILITY TESTS PASSED")
print("=" * 65)
