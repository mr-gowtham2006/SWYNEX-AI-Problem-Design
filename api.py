"""
AI SMS Safety Analyzer — SWYNEX Technologies AI Internship
FastAPI API Layer for AI SMS Safety Analyzer

Exposes the existing, tested detection pipeline through a clean HTTP/JSON interface.
Directly reuses:
  - Task 2 model / TF-IDF transform
  - Task 3 analyze_message() engine
  - barb-phish local URL forensics
  - Task 4.4 synthesize_risk()
  - Task 4.5 explain_prediction()
  - Task 4.6 get_safety_guidance() & get_official_reporting_info()
"""

import sys
import os
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# PATH SETUP
# Ensure task-3/ and workspace root are importable
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_TASK3_DIR = os.path.join(_BASE_DIR, "task-3")
if _TASK3_DIR not in sys.path:
    sys.path.insert(0, _TASK3_DIR)
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

# ---------------------------------------------------------------------------
# IMPORT EXISTING TESTED LOGIC FROM app.py
# Does NOT duplicate any detection, scoring, or guidance algorithms.
# ---------------------------------------------------------------------------
from app import (
    analyze_message,
    model,
    _MODEL_LOADED,
    _MODEL_ERROR,
    extract_urls,
    defang_url,
    analyze_url,
    synthesize_risk,
    explain_prediction,
    get_safety_guidance,
    get_official_reporting_info,
)


# ---------------------------------------------------------------------------
# PYDANTIC REQUEST & RESPONSE SCHEMAS
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str = Field(..., description="The SMS message text to analyze")
    sender_id: Optional[str] = Field(None, description="Optional SMS sender header or phone number")


class UrlAnalysisItem(BaseModel):
    url: str
    defanged_url: str
    exit_code: Optional[int] = None
    verdict: Optional[str] = None
    risk_score: Optional[float] = None
    signals: List[Dict[str, Any]] = []
    error: Optional[str] = None


class FeatureContribution(BaseModel):
    token: str
    contribution: float
    weight: float
    direction: str


class ExplainabilityResult(BaseModel):
    has_features: bool
    nnz: int
    spam_features: List[FeatureContribution] = []
    ham_features: List[FeatureContribution] = []
    summary: str


class SafetyGuidance(BaseModel):
    title: str
    alert_type: str
    actions: List[str]


class OfficialReportingChannel(BaseModel):
    agency: str
    portal: str
    purpose: str
    url: str
    action: str


class SenderIdInfo(BaseModel):
    sender_id: Optional[str] = None
    is_valid_format: Optional[bool] = None
    note: Optional[str] = None
    trai_portal_url: str = "https://smsheader.trai.gov.in"


class AnalyzeResponse(BaseModel):
    # Overall synthesized verdict
    overall_state: str  # "SCAM", "SPAM", "UNCERTAIN", "NO THREAT DETECTED"
    reason: str
    rule: str
    action_recommendation: str

    # Core SMS model output
    prediction: str     # "SPAM" or "NOT SPAM"
    confidence: float   # 0.0 to 100.0
    risk_level: str     # "LOW", "MEDIUM", "HIGH"
    indicators: List[str] = []
    tokens_matched: int = 0  # TF-IDF nnz count

    # Detailed sub-system results
    urls_detected: int = 0
    url_analysis: List[UrlAnalysisItem] = []
    explainability: ExplainabilityResult
    safety_guidance: SafetyGuidance
    official_reporting: List[OfficialReportingChannel]
    sender_info: Optional[SenderIdInfo] = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_error: Optional[str] = None
    model_name: str
    barb_phish_available: bool


# ---------------------------------------------------------------------------
# CONSTANTS & LOOKUPS
# Same display mappings used by Streamlit in app.py
# ---------------------------------------------------------------------------
_ACTION_RECOMMENDATIONS = {
    "SCAM": "⛔ Do NOT click any links or share OTPs.",
    "SPAM": "🚫 Block sender — do not reply or click links.",
    "UNCERTAIN": "⚠️ Proceed with caution — verify sender independently.",
    "NO THREAT DETECTED": "✔️ No immediate action required.",
}


# ---------------------------------------------------------------------------
# FASTAPI APPLICATION SETUP
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI SMS Safety Analyzer API",
    description="REST API exposing the AI SMS Safety Analyzer detection pipeline, URL forensics, and explainability.",
    version="1.0.0",
)

# Enable CORS for local development and production Netlify frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://safesms.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["System"])
def get_health():
    """Return system and model health status."""
    import shutil
    barb_available = shutil.which("barb") is not None

    return HealthResponse(
        status="healthy" if _MODEL_LOADED else "degraded",
        model_loaded=_MODEL_LOADED,
        model_error=_MODEL_ERROR if not _MODEL_LOADED else None,
        model_name="TF-IDF + Logistic Regression SMS Classifier (scikit-learn 1.6.1)",
        barb_phish_available=barb_available,
    )


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
def analyze_sms(payload: AnalyzeRequest):
    """
    Execute full security analysis on an SMS message.
    Calls the exact existing logic: Task 3, barb-phish, risk synthesis,
    explainability, and safety guidance.
    """
    sms_text = payload.message

    # 1. Edge case: Empty or whitespace-only message
    if not sms_text or not sms_text.strip():
        t3_result = analyze_message(sms_text)
        nnz = 0
        raw_url_results = []
        synthesis = synthesize_risk(t3_result, raw_url_results, nnz=nnz)
        raw_explanation = explain_prediction(sms_text)
        overall_state = synthesis["state"]
        guidance = get_safety_guidance(overall_state, t3_result, raw_url_results)
        reporting = get_official_reporting_info()

        return AnalyzeResponse(
            overall_state=overall_state,
            reason=synthesis["reason"],
            rule=synthesis.get("rule", "ERROR_INPUT"),
            action_recommendation=_ACTION_RECOMMENDATIONS.get(overall_state, ""),
            prediction=t3_result.get("prediction", "NOT SPAM"),
            confidence=float(t3_result.get("confidence", 0.0)),
            risk_level=t3_result.get("risk_level", "LOW"),
            indicators=t3_result.get("indicators", []),
            tokens_matched=0,
            urls_detected=0,
            url_analysis=[],
            explainability=ExplainabilityResult(
                has_features=raw_explanation.get("has_features", False),
                nnz=raw_explanation.get("nnz", 0),
                spam_features=[],
                ham_features=[],
                summary=raw_explanation.get("summary", "No message content provided."),
            ),
            safety_guidance=SafetyGuidance(**guidance),
            official_reporting=[OfficialReportingChannel(**r) for r in reporting],
            sender_info=None,
        )

    # 2. Task 3 SMS classification
    t3_result = analyze_message(sms_text)

    # 3. TF-IDF non-zero vocabulary count (nnz) for OOV detection
    nnz = 0
    if _MODEL_LOADED and model is not None:
        try:
            vec = model.named_steps["tfidf"].transform([sms_text])
            nnz = int(vec.nnz)
        except Exception:
            nnz = 0

    # 4. Task 4.3 URL extraction and local analysis via barb-phish
    extracted_urls = extract_urls(sms_text)
    raw_url_results = [analyze_url(u) for u in extracted_urls]

    # Convert to typed UrlAnalysisItem with defanged URLs
    url_items: List[UrlAnalysisItem] = []
    for r in raw_url_results:
        url_items.append(
            UrlAnalysisItem(
                url=r["url"],
                defanged_url=defang_url(r["url"]),
                exit_code=r.get("exit_code"),
                verdict=r.get("verdict"),
                risk_score=r.get("risk_score"),
                signals=r.get("signals") or [],
                error=r.get("error"),
            )
        )

    # 5. Task 4.4 Risk synthesis
    synthesis = synthesize_risk(t3_result, raw_url_results, nnz=nnz)
    overall_state = synthesis["state"]

    # 6. Task 4.5 Feature-level explainability
    raw_explanation = explain_prediction(sms_text)
    explanation_obj = ExplainabilityResult(
        has_features=raw_explanation.get("has_features", False),
        nnz=raw_explanation.get("nnz", 0),
        spam_features=[FeatureContribution(**f) for f in raw_explanation.get("spam_features", [])],
        ham_features=[FeatureContribution(**f) for f in raw_explanation.get("ham_features", [])],
        summary=raw_explanation.get("summary", ""),
    )

    # 7. Task 4.6 Safety guidance
    raw_guidance = get_safety_guidance(overall_state, t3_result, raw_url_results)
    guidance_obj = SafetyGuidance(
        title=raw_guidance.get("title", "Recommended Actions"),
        alert_type=raw_guidance.get("alert_type", "info"),
        actions=raw_guidance.get("actions", []),
    )

    # 8. Task 4.6 Official reporting channels
    raw_reporting = get_official_reporting_info()
    reporting_items = [OfficialReportingChannel(**r) for r in raw_reporting]

    # 9. Sender ID analysis (if provided)
    sender_info_obj: Optional[SenderIdInfo] = None
    if payload.sender_id and payload.sender_id.strip():
        s_id = payload.sender_id.strip().upper()
        # TRAI commercial header format: two-letter prefix, hyphen, six-character entity code (e.g. VK-HDFCBK)
        is_commercial = bool(re.match(r"^[A-Z0-9]{2}-[A-Z0-9]{6}$", s_id))
        is_phone_number = bool(re.match(r"^(\+?91)?[6-9]\d{9}$", s_id.replace(" ", "").replace("-", "")))

        if is_commercial:
            note = f"Header '{s_id}' matches standard TRAI commercial format (XY-ABCDEF). Verify entity on TRAI portal."
        elif is_phone_number:
            note = f"Sender appears to be an individual 10-digit mobile number ({s_id}). Banks and government bodies never send official SMS from personal numbers."
        else:
            note = f"Header '{s_id}' does not match standard TRAI commercial format (XY-ABCDEF)."

        sender_info_obj = SenderIdInfo(
            sender_id=s_id,
            is_valid_format=is_commercial,
            note=note,
            trai_portal_url="https://smsheader.trai.gov.in",
        )

    # 10. Assemble complete response
    return AnalyzeResponse(
        overall_state=overall_state,
        reason=synthesis.get("reason", ""),
        rule=synthesis.get("rule", "UNKNOWN"),
        action_recommendation=_ACTION_RECOMMENDATIONS.get(overall_state, "Proceed with caution."),
        prediction=t3_result.get("prediction", "NOT SPAM"),
        confidence=float(t3_result.get("confidence", 0.0)),
        risk_level=t3_result.get("risk_level", "LOW"),
        indicators=t3_result.get("indicators", []),
        tokens_matched=nnz,
        urls_detected=len(extracted_urls),
        url_analysis=url_items,
        explainability=explanation_obj,
        safety_guidance=guidance_obj,
        official_reporting=reporting_items,
        sender_info=sender_info_obj,
    )
