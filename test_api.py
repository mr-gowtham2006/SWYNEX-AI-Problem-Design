"""
Test Suite for AI SMS Safety Analyzer FastAPI Layer (api.py)
Validates endpoints, schema contract, and detection consistency.
"""

from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


def test_health_endpoint():
    """Verify GET /api/health returns 200 OK and model status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "TF-IDF" in data["model_name"]
    assert "barb_phish_available" in data


def test_analyze_normal_sms():
    """Verify normal message without URLs returns NO THREAT DETECTED."""
    payload = {
        "message": "Hey, are we still meeting for lunch at 12?",
        "sender_id": "FRIEND",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_state"] == "NO THREAT DETECTED"
    assert data["rule"] == "NO_THREAT"
    assert data["prediction"] == "NOT SPAM"
    assert data["urls_detected"] == 0
    assert len(data["safety_guidance"]["actions"]) > 0
    assert len(data["official_reporting"]) == 4


def test_analyze_obvious_spam():
    """Verify high-confidence promotional spam returns SPAM."""
    payload = {
        "message": "URGENT! You have won a 1 week FREE membership in our $100,000 prize jackpot! Call 09061743810 now",
        "sender_id": "PRIZE-ALERT",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_state"] == "SPAM"
    assert data["rule"] == "HIGH_CONFIDENCE_SPAM"
    assert data["prediction"] == "SPAM"
    assert data["confidence"] > 50.0
    assert len(data["indicators"]) >= 3


def test_analyze_phishing_url():
    """Verify phishing URL returns SCAM."""
    payload = {
        "message": "Please update your security settings http://paypal.com.account-verification-login.com immediately",
        "sender_id": "+919876543210",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_state"] == "SCAM"
    assert data["urls_detected"] == 1
    assert data["url_analysis"][0]["defanged_url"].startswith("hxxp[://]")
    assert data["sender_info"] is not None
    assert "10-digit mobile number" in data["sender_info"]["note"]


def test_analyze_suspicious_url_benign_sms():
    """Verify suspicious link with benign text yields UNCERTAIN (conflicting evidence)."""
    payload = {
        "message": "Hey check this link http://suspicious-login.update-paypal.com",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    # If URL is suspicious and text is NOT SPAM, rule is SUSPICIOUS_URL_CONFLICT
    assert data["overall_state"] == "UNCERTAIN"
    assert data["rule"] == "SUSPICIOUS_URL_CONFLICT"


def test_analyze_hinglish_oov():
    """Verify pure Hinglish/unseen vocabulary message yields UNCERTAIN."""
    payload = {
        "message": "Bhai jaldi paisa bhej de gpay pe",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_state"] == "UNCERTAIN"
    assert data["tokens_matched"] == 0
    assert data["rule"] == "OUT_OF_VOCABULARY"
    assert data["explainability"]["has_features"] is False


def test_analyze_empty_input():
    """Verify empty input returns UNCERTAIN with ERROR_INPUT rule without crashing."""
    payload = {
        "message": "",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_state"] == "UNCERTAIN"
    assert data["rule"] == "ERROR_INPUT"
    assert "incomplete" in data["reason"].lower()


def test_analyze_multiple_urls():
    """Verify message with multiple URLs is properly extracted and analyzed."""
    payload = {
        "message": "Check our main site at https://google.com or visit http://suspicious-login.update-paypal.com for updates",
        "sender_id": "VK-HDFCBK",
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["urls_detected"] == 2
    assert len(data["url_analysis"]) == 2
    assert data["sender_info"]["is_valid_format"] is True


if __name__ == "__main__":
    test_health_endpoint()
    print("test_health_endpoint PASSED")
    test_analyze_normal_sms()
    print("test_analyze_normal_sms PASSED")
    test_analyze_obvious_spam()
    print("test_analyze_obvious_spam PASSED")
    test_analyze_phishing_url()
    print("test_analyze_phishing_url PASSED")
    test_analyze_suspicious_url_benign_sms()
    print("test_analyze_suspicious_url_benign_sms PASSED")
    test_analyze_hinglish_oov()
    print("test_analyze_hinglish_oov PASSED")
    test_analyze_empty_input()
    print("test_analyze_empty_input PASSED")
    test_analyze_multiple_urls()
    print("test_analyze_multiple_urls PASSED")
    print("\nALL API TESTS PASSED SUCCESSFULLY!")
