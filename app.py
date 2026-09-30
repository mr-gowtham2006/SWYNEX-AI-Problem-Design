"""
AI SMS Safety Analyzer — SWYNEX Technologies AI Internship
Task 4: Final AI Application

app.py — Streamlit application entry point

TASK 4.1: Application skeleton and UI layout.
TASK 4.2: Integrated Task 3 analyze_message() engine.
TASK 4.3: Local URL analysis via barb-phish CLI.
           Risk synthesis and explainability will be added in Tasks 4.4-4.5.
"""

import sys
import os
import re
import json
import subprocess
import warnings
import streamlit as st

# ---------------------------------------------------------------------------
# PATH SETUP
# Ensure task-3/ is importable regardless of where `streamlit run` is called.
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_TASK3_DIR = os.path.join(_BASE_DIR, "task-3")
if _TASK3_DIR not in sys.path:
    sys.path.insert(0, _TASK3_DIR)

# ---------------------------------------------------------------------------
# IMPORT TASK 3
# intelligent_detector.py loads spam_classifier.pkl at import time.
# sklearn 1.6.1 is pinned in the venv to match serialization version exactly.
# ---------------------------------------------------------------------------
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from intelligent_detector import analyze_message, model
        _MODEL_LOADED = True
        _MODEL_ERROR = ""
    except FileNotFoundError as e:
        _MODEL_LOADED = False
        _MODEL_ERROR = str(e)
    except Exception as e:
        _MODEL_LOADED = False
        _MODEL_ERROR = str(e)


# ---------------------------------------------------------------------------
# TASK 4.3 — URL ANALYSIS HELPERS
# Kept fully separate from Task 3 spam classification logic.
# ---------------------------------------------------------------------------

# Regex: match http(s):// or www. URLs; stop at whitespace or common
# trailing punctuation (comma, period, ), >, ]).
_URL_PATTERN = re.compile(
    r"https?://[^\s,)<>\]\"']+"
    r"|www\.[^\s,)<>\]\"']+"
)

# Exit-code semantics defined by barb-phish 1.8.0 official documentation.
_BARB_EXIT_LABELS = {
    0: ("SAFE",       "🟢"),
    1: ("SUSPICIOUS", "🟡"),
    2: ("PHISHING",   "🔴"),
    3: ("ERROR",      "⚪"),
}

_URL_TIMEOUT_SECONDS = 10  # per-URL timeout; barb is fully local so 10s is generous


def extract_urls(message: str) -> list:
    """
    Extract all URLs from a message using a regex pre-filter.
    Only strings matching http(s):// or www. prefixes are returned.
    This prevents malformed non-URL strings from being sent to barb-phish.
    """
    return _URL_PATTERN.findall(message)


def analyze_url(url: str) -> dict:
    """
    Invoke barb-phish CLI locally against a single URL.
    Returns a result dict with keys:
        url          (str)  — original URL
        exit_code    (int)  — 0/1/2/3/-1/-2
        verdict      (str)  — from barb JSON or derived label
        risk_score   (float|None)
        signals      (list) — list of signal dicts from barb
        raw          (dict|None) — full parsed JSON or None
        error        (str|None) — human-readable error if applicable
    """
    result = {
        "url": url,
        "exit_code": None,
        "verdict": None,
        "risk_score": None,
        "signals": [],
        "raw": None,
        "error": None,
    }

    try:
        # barb-phish is fully local/offline for core analysis.
        # --osint flag is deliberately NOT used (would trigger network calls).
        output = subprocess.check_output(
            ["barb", "analyze", url, "-o", "json"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=_URL_TIMEOUT_SECONDS,
        )
        result["exit_code"] = 0

    except subprocess.CalledProcessError as e:
        # barb exits non-zero for suspicious (1), phishing (2), error (3).
        # The JSON output is still valid and must be parsed.
        output = e.output
        result["exit_code"] = e.returncode

    except FileNotFoundError:
        # barb not installed or not on PATH.
        result["exit_code"] = -1
        result["verdict"] = "UNAVAILABLE"
        result["error"] = (
            "barb-phish is not installed or not found on PATH. "
            "URL analysis is unavailable."
        )
        return result

    except subprocess.TimeoutExpired:
        result["exit_code"] = -2
        result["verdict"] = "TIMEOUT"
        result["error"] = (
            f"barb-phish did not respond within {_URL_TIMEOUT_SECONDS}s. "
            "URL analysis timed out."
        )
        return result

    # Parse JSON output (valid for exit codes 0, 1, 2; may be partial for 3).
    try:
        parsed = json.loads(output)
        result["raw"] = parsed
        result["verdict"] = parsed.get("verdict", _BARB_EXIT_LABELS.get(result["exit_code"], ("UNKNOWN",))[0])
        result["risk_score"] = parsed.get("risk_score")
        result["signals"] = parsed.get("signals", [])
    except (json.JSONDecodeError, ValueError):
        # barb exit code 3 (internal error) may produce non-JSON output.
        result["verdict"] = "ERROR"
        result["error"] = (
            "barb-phish returned an unexpected response. "
            "URL analysis could not be completed for this URL."
        )

    return result


# ---------------------------------------------------------------------------
# TASK 4.4 — RISK SYNTHESIS & UNCERTAINTY LOGIC
# ---------------------------------------------------------------------------

def synthesize_risk(t3_result: dict, url_results: list, nnz: int | None = None) -> dict:
    """
    Synthesize Task 3 SMS classification and Task 4.3 URL analysis into an
    overall application-level safety assessment.

    Overall States:
      - SCAM
      - SPAM
      - UNCERTAIN
      - NO THREAT DETECTED

    Deterministic Priority Order:
      1. Phishing URL detected -> SCAM
      2. Suspicious URL + suspicious SMS content/indicators -> SCAM
      3. Suspicious URL + normal SMS text (conflicting evidence) -> UNCERTAIN
      4. Failed/unavailable URL analysis when a URL is present -> UNCERTAIN
      5. Pure OOV (nnz == 0) -> UNCERTAIN
      6. Task 3 SPAM with adequate confidence (>= 85%) or >= 3 indicators -> SPAM
      7. Task 3 SPAM with borderline confidence (< 85%) -> UNCERTAIN
      8. Task 3 NOT SPAM with confidence < 70% -> UNCERTAIN
      9. Clean message (NOT SPAM, conf >= 70%, no threat URLs, nnz > 0) -> NO THREAT DETECTED
    """
    if not t3_result or "error" in t3_result:
        return {
            "state": "UNCERTAIN",
            "reason": "Analysis incomplete due to input validation or processing error.",
            "rule": "ERROR_INPUT",
        }

    prediction = t3_result.get("prediction", "NOT SPAM")
    confidence = t3_result.get("confidence", 0.0)
    indicators = t3_result.get("indicators", [])

    has_phishing_url = any(
        u.get("exit_code") == 2 or u.get("verdict") == "PHISHING"
        for u in url_results
    )
    has_suspicious_url = any(
        u.get("exit_code") == 1 or u.get("verdict") in ("SUSPICIOUS", "HIGH_RISK")
        for u in url_results
    )
    has_url_error = any(
        u.get("exit_code") in (-1, -2, 3) or u.get("error")
        for u in url_results
    )

    # 1. Any URL identified as PHISHING -> SCAM (overrides everything)
    if has_phishing_url:
        return {
            "state": "SCAM",
            "reason": "High-risk phishing link detected by local URL analysis.",
            "rule": "PHISHING_URL",
        }

    # SMS text indicators (excluding the generic 'Contains a web link' indicator added to all URL messages)
    suspicious_text_indicators = [
        ind for ind in indicators if ind != "Contains a web link"
    ]

    # 2. Suspicious URL + suspicious SMS evidence (SPAM prediction or suspicious text indicators) -> SCAM
    if has_suspicious_url and (prediction == "SPAM" or len(suspicious_text_indicators) > 0):
        return {
            "state": "SCAM",
            "reason": "Suspicious URL detected alongside suspicious message content or indicators.",
            "rule": "SUSPICIOUS_URL_WITH_SMS_INDICATORS",
        }

    # 3. Suspicious URL + Normal SMS (no indicators, NOT SPAM) -> Conflicting evidence -> UNCERTAIN
    if has_suspicious_url:
        return {
            "state": "UNCERTAIN",
            "reason": "URL analysis flagged suspicious characteristics, but message text appears benign. Manual review recommended.",
            "rule": "SUSPICIOUS_URL_CONFLICT",
        }

    # 4. URL analysis failed, unavailable, or timed out when URL(s) exist -> UNCERTAIN
    if has_url_error:
        return {
            "state": "UNCERTAIN",
            "reason": "Message contains a web link, but local URL security check could not be completed.",
            "rule": "URL_ANALYSIS_FAILED",
        }

    # 5. Out-of-vocabulary (pure Hinglish, code-mixed, or obfuscated text with nnz == 0) -> UNCERTAIN
    if nnz is not None and nnz == 0:
        return {
            "state": "UNCERTAIN",
            "reason": "Message contains no recognized vocabulary terms (unseen language, Hinglish, or obfuscated characters).",
            "rule": "OUT_OF_VOCABULARY",
        }

    # 6. Task 3 SPAM
    if prediction == "SPAM":
        if confidence >= 85.0 or len(indicators) >= 3:
            return {
                "state": "SPAM",
                "reason": f"Classified as spam with {confidence:.1f}% confidence and {len(indicators)} indicator(s).",
                "rule": "HIGH_CONFIDENCE_SPAM",
            }
        else:
            return {
                "state": "UNCERTAIN",
                "reason": f"Message leans toward spam, but confidence ({confidence:.1f}%) is borderline. Manual review recommended.",
                "rule": "BORDERLINE_SPAM",
            }

    # 7. Task 3 NOT SPAM but confidence < 70% -> UNCERTAIN
    if confidence < 70.0:
        return {
            "state": "UNCERTAIN",
            "reason": f"Message classified as not spam, but model confidence is low ({confidence:.1f}% < 70%). Manual review recommended.",
            "rule": "LOW_CONFIDENCE_HAM",
        }

    # 8. Clean message -> NO THREAT DETECTED
    return {
        "state": "NO THREAT DETECTED",
        "reason": "No scam or spam indicators detected. The message appears normal.",
        "rule": "NO_THREAT",
    }


# ---------------------------------------------------------------------------
# TASK 4.5 — EXPLAINABILITY (TF-IDF FEATURE INFLUENCE)
# ---------------------------------------------------------------------------

def explain_prediction(message: str, top_k: int = 5) -> dict:
    """
    Explain the model's decision using the learned TF-IDF feature weights
    and Logistic Regression linear coefficients.

    Contribution = feature_tfidf_value * logistic_regression_weight
      - Positive contribution (> 0): pushed the model toward SPAM
      - Negative contribution (< 0): pushed the model toward NOT SPAM

    Returns a dict with:
      - has_features (bool): True if message contains at least 1 vocabulary term
      - nnz (int): number of recognized tokens
      - spam_features (list[dict]): top terms pushing toward SPAM
      - ham_features (list[dict]): top terms pushing toward NOT SPAM
      - summary (str): concise, plain-language explanation
    """
    result = {
        "has_features": False,
        "nnz": 0,
        "spam_features": [],
        "ham_features": [],
        "summary": "No explanation available.",
    }

    if not isinstance(message, str) or not message.strip():
        result["summary"] = "No message content provided for model feature explanation."
        return result

    if not _MODEL_LOADED or model is None:
        result["summary"] = "Model not loaded; feature explanation is unavailable."
        return result

    try:
        tfidf = model.named_steps["tfidf"]
        clf = model.named_steps["classifier"]

        vec = tfidf.transform([message])
        nnz = vec.nnz
        result["nnz"] = nnz

        if nnz == 0:
            result["has_features"] = False
            result["summary"] = (
                "The model did not recognize any learned vocabulary features in this message "
                "(possible unseen language, Hinglish, or obfuscated characters). "
                "The model therefore has limited textual evidence for its prediction."
            )
            return result

        result["has_features"] = True
        feature_names = tfidf.get_feature_names_out()
        coefs = clf.coef_[0]

        indices = vec.indices
        data = vec.data

        contributions = []
        for i, idx in enumerate(indices):
            contrib = float(data[i] * coefs[idx])
            token = feature_names[idx]
            contributions.append({
                "token": token,
                "contribution": round(contrib, 4),
                "weight": round(float(coefs[idx]), 4),
                "direction": "SPAM" if contrib > 0 else "NOT SPAM",
            })

        # Separate positive (spam-leaning) and negative (ham-leaning)
        spam_tokens = [c for c in contributions if c["contribution"] > 0]
        ham_tokens = [c for c in contributions if c["contribution"] < 0]

        # Sort by magnitude of contribution
        spam_tokens.sort(key=lambda x: x["contribution"], reverse=True)
        ham_tokens.sort(key=lambda x: abs(x["contribution"]), reverse=True)

        result["spam_features"] = spam_tokens[:top_k]
        result["ham_features"] = ham_tokens[:top_k]

        # Plain language summary
        if spam_tokens and not ham_tokens:
            top_words = ", ".join(f"'{s['token']}'" for s in spam_tokens[:3])
            result["summary"] = f"The terms {top_words} pushed the model toward the SPAM classification."
        elif ham_tokens and not spam_tokens:
            top_words = ", ".join(f"'{h['token']}'" for h in ham_tokens[:3])
            result["summary"] = f"The terms {top_words} pushed the model toward the NOT SPAM classification."
        elif spam_tokens and ham_tokens:
            top_spam_words = ", ".join(f"'{s['token']}'" for s in spam_tokens[:2])
            top_ham_words = ", ".join(f"'{h['token']}'" for h in ham_tokens[:2])
            result["summary"] = (
                f"Mixed evidence: {top_spam_words} pushed toward SPAM, "
                f"while {top_ham_words} pushed toward NOT SPAM."
            )
        else:
            result["summary"] = "Features contributed neutrally to the classification."

        return result

    except Exception as e:
        result["summary"] = f"Could not generate feature explanation: {e}"
        return result


# ---------------------------------------------------------------------------
# TASK 4.6 — SAFETY GUIDANCE & OFFICIAL REPORTING
# ---------------------------------------------------------------------------

def get_safety_guidance(overall_state: str, task3_result: dict, url_results: list) -> dict:
    """
    Generate evidence-based actionable safety guidance tailored to the
    synthesized risk state.

    Overall states:
      - SCAM
      - SPAM
      - UNCERTAIN
      - NO THREAT DETECTED
    """
    guidance = {
        "title": "Recommended Actions",
        "actions": [],
        "alert_type": "info",
    }

    if overall_state == "SCAM":
        guidance["alert_type"] = "error"
        guidance["actions"] = [
            "**Do NOT click any links** contained in this message. The analyzer detected high-risk or suspicious indicators.",
            "**Never share confidential information**: Banks, government agencies, and legitimate service providers never request OTPs, UPI PINs, passwords, or CVV numbers over SMS.",
            "**Do NOT transfer money** or call phone numbers mentioned in the message text.",
            "**Verify independently**: If the message claims your account or service is blocked, log in directly via the provider's official verified app or official website URL.",
            "**Report the message**: If money was siphoned or fraud occurred, report immediately to the National Cyber Crime Helpline at `1930` or file a complaint at `https://cybercrime.gov.in`. Report the fraudulent sender to DoT Chakshu at `https://www.sancharsaathi.gov.in/sfc/`.",
        ]

    elif overall_state == "SPAM":
        guidance["alert_type"] = "warning"
        guidance["actions"] = [
            "**Do NOT click promotional links** or claim offers from unverified senders.",
            "**Do NOT reply to the SMS**: Replying (e.g. 'STOP') to unregistered numbers often confirms your phone number is active to spam lists.",
            "**Block the sender** using your phone's built-in SMS spam filter.",
            "**Report Unsolicited Commercial Communication (UCC)**: Forward the message to your telecom service provider via `1909` (Call or SMS format: `COMP <brief description>, <sender ID/number>, <dd/mm/yy>`) within 3 days, or use the TRAI DND 3.0 mobile application.",
        ]

    elif overall_state == "UNCERTAIN":
        guidance["alert_type"] = "info"
        guidance["actions"] = [
            "**Do not assume the message is safe**: The analyzer encountered borderline confidence, unlearned language/vocabulary, or conflicting evidence.",
            "**Verify the sender independently**: Look up the organization's official customer support number from their verified website or the back of your payment card.",
            "**Avoid clicking links or downloading attachments** until the communication is verified.",
            "**Treat urgency with caution**: Scams frequently manufacture artificial deadlines or threats of service disruption.",
        ]

    else:  # NO THREAT DETECTED
        guidance["alert_type"] = "success"
        guidance["actions"] = [
            "**No strong threat indicators detected**: The message appears normal based on model evaluation and local URL heuristics.",
            "**Exercise normal security hygiene**: Automated tools cannot guarantee complete protection against evolving threats. Always exercise caution with unsolicited messages.",
            "**Never disclose OTPs or security codes**: Legitimate organizations will never ask you to disclose your one-time passwords.",
            "**Confirm sender legitimacy**: Check that the sender header matches standard organizational formats (e.g., `XY-ABCDEF`).",
        ]

    return guidance


def get_official_reporting_info() -> list:
    """
    Return verified official Government of India reporting channels.
    Strictly attributed to their correct operating agencies:
      - TRAI (Telecom Regulatory Authority of India)
      - DoT (Department of Telecommunications, Ministry of Communications)
      - MHA / I4C (Ministry of Home Affairs / Indian Cybercrime Coordination Centre)
    """
    return [
        {
            "agency": "Department of Telecommunications (DoT)",
            "portal": "Sanchar Saathi — Chakshu (चक्षु)",
            "purpose": "Report suspected fraud communications received via Call, SMS, WhatsApp, or suspected phishing web links.",
            "url": "https://www.sancharsaathi.gov.in/sfc/",
            "action": "Submit suspected fraud details, headers, or web links directly to DoT for investigation.",
        },
        {
            "agency": "Telecom Regulatory Authority of India (TRAI)",
            "portal": "Header Information Portal",
            "purpose": "Verify the registered Principal Entity behind an SMS sender ID / header (format: XY-ABCDEF).",
            "url": "https://smsheader.trai.gov.in",
            "action": "Look up whether a commercial header belongs to a legitimate registered organization.",
        },
        {
            "agency": "Telecom Regulatory Authority of India (TRAI)",
            "portal": "DND 1909 / UCC Complaint Mechanism",
            "purpose": "Report Unsolicited Commercial Communication (UCC / spam) to your telecom operator.",
            "url": "https://www.trai.gov.in",
            "action": "Send SMS to 1909: `COMP <brief description>, <sender ID/number>, <dd/mm/yy>` within 3 days of receiving the spam, or report via TRAI DND 3.0 app.",
        },
        {
            "agency": "Ministry of Home Affairs (MHA) / I4C",
            "portal": "National Cyber Crime Reporting Portal",
            "purpose": "Report cybercrimes and financial cyber fraud (immediate freezing of fraudulent transactions).",
            "url": "https://cybercrime.gov.in",
            "action": "Dial toll-free National Cybercrime Helpline `1930` or file an online complaint at `https://cybercrime.gov.in`.",
        },
    ]


# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AI SMS Safety Analyzer",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------
st.title("🔍 AI SMS Safety Analyzer")
st.caption("SWYNEX Technologies · AI Internship · Task 4")

st.markdown(
    """
    Paste an SMS message below to check whether it may be **spam, a scam,
    or a phishing attempt**. All analysis runs locally on this device —
    no message content is sent to any external server.
    """
)

# Warn prominently if the model failed to load — do not silently fail.
if not _MODEL_LOADED:
    st.error(
        "**Analysis engine could not be loaded.**\n\n"
        "Make sure `task-2/spam_classifier.pkl` exists relative to `app.py`.\n\n"
        f"Details: {_MODEL_ERROR}",
        icon="🚨",
    )

st.divider()

# ---------------------------------------------------------------------------
# INPUT SECTION
# ---------------------------------------------------------------------------
st.subheader("📩 Enter SMS Message")

sms_input = st.text_area(
    label="SMS Message",
    placeholder="Paste your SMS here...",
    height=150,
    max_chars=5000,
    help="Maximum 5000 characters. Paste the full SMS text you received.",
    label_visibility="collapsed",
)

char_count = len(sms_input)
if char_count > 0:
    st.caption(f"{char_count} / 5000 characters")

st.subheader("📋 Sender ID (optional)")

sender_id_input = st.text_input(
    label="Sender ID",
    placeholder="e.g. VK-HDFCBK, AM-AMAZON, or a phone number",
    help=(
        "Enter the Sender ID or phone number that appeared in the SMS. "
        "This is used to provide TRAI header verification guidance."
    ),
    label_visibility="collapsed",
)

st.divider()

# ---------------------------------------------------------------------------
# ANALYZE BUTTON
# ---------------------------------------------------------------------------
analyze_button = st.button(
    "🔍 Analyze Message",
    type="primary",
    use_container_width=True,
    disabled=(char_count == 0 or not _MODEL_LOADED),
)

# ---------------------------------------------------------------------------
# RESULT AREA
# ---------------------------------------------------------------------------
if analyze_button:
    if not sms_input.strip():
        st.error("Please enter an SMS message before analyzing.")
    else:
        with st.spinner("Analyzing..."):
            # Task 3: SMS classification (unchanged)
            t3_result = analyze_message(sms_input)

            # Compute TF-IDF non-zero vocabulary count (nnz) for OOV detection
            nnz = None
            if _MODEL_LOADED:
                try:
                    vec = model.named_steps["tfidf"].transform([sms_input])
                    nnz = vec.nnz
                except Exception:
                    nnz = None

            # Task 4.3: URL extraction and local analysis
            urls = extract_urls(sms_input)
            url_results = [analyze_url(u) for u in urls]

            # Task 4.4: Overall Risk Synthesis
            synthesis_result = synthesize_risk(t3_result, url_results, nnz=nnz)

            # Task 4.5: Feature-level explainability
            explanation_result = explain_prediction(sms_input)

        st.divider()
        st.subheader("📊 Analysis Result")

        # ------------------------------------------------------------------
        # ERROR PATH — Task 3 returned a validation/runtime error
        # ------------------------------------------------------------------
        if "error" in t3_result:
            st.error(f"{t3_result['error']}", icon="🚨")

        # ------------------------------------------------------------------
        # SUCCESS PATH — Task 3 returned a full analysis dict
        # ------------------------------------------------------------------
        else:
            prediction  = t3_result["prediction"]   # "SPAM" or "NOT SPAM"
            confidence  = t3_result["confidence"]   # float
            risk_level  = t3_result["risk_level"]   # "LOW" / "MEDIUM" / "HIGH"
            indicators  = t3_result["indicators"]   # list[str]
            explanation = t3_result["explanation"]  # str

            # ---- Prediction badge ----
            if prediction == "SPAM":
                st.error(f"🚨  **{prediction}**", icon="🚨")
            else:
                st.success(f"✅  **{prediction}**", icon="✅")

            # ---- Metrics row ----
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(label="Prediction", value=prediction)
            with col2:
                st.metric(label="Confidence", value=f"{confidence:.2f}%")
            with col3:
                risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(
                    risk_level, ""
                )
                st.metric(label="Risk Level", value=f"{risk_emoji} {risk_level}")

            st.divider()

            # ---- Explanation ----
            st.markdown(f"**ℹ️ Explanation:** {explanation}")

            # ---- Suspicious indicators ----
            st.markdown("**🔎 Suspicious Indicators:**")
            if indicators:
                for indicator in indicators:
                    st.markdown(f"- {indicator}")
            else:
                st.markdown("- None detected")

            # ------------------------------------------------------------------
            # TASK 4.3 — URL ANALYSIS RESULTS
            # Note: URL results are displayed independently.
            # Risk synthesis (combining URL + SMS verdicts) is TASK 4.4.
            # ------------------------------------------------------------------
            st.divider()
            st.subheader("🔗 URL Analysis")

            if not urls:
                st.info("No URLs detected in this message.", icon="ℹ️")
            else:
                st.caption(f"{len(urls)} URL(s) found — analyzed locally using barb-phish (offline, no data sent externally).")

                for ur in url_results:
                    exit_code = ur["exit_code"]
                    verdict   = ur["verdict"] or "UNKNOWN"
                    label, emoji = _BARB_EXIT_LABELS.get(exit_code, ("UNKNOWN", "⚪"))

                    with st.expander(f"{emoji} {verdict}  —  {ur['url']}", expanded=True):

                        if ur["error"]:
                            st.warning(ur["error"])

                        else:
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.metric("Verdict", f"{emoji} {verdict}")
                            with col_b:
                                score_display = (
                                    f"{ur['risk_score']:.1f}"
                                    if ur["risk_score"] is not None
                                    else "N/A"
                                )
                                st.metric("Risk Score", score_display)

                            if ur["signals"]:
                                st.markdown("**Signals detected:**")
                                for sig in ur["signals"]:
                                    sev   = sig.get("severity", "")
                                    lbl   = sig.get("label", "")
                                    detail = sig.get("detail", "")
                                    sev_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
                                    st.markdown(f"- {sev_emoji} **{lbl}**: {detail}")
                            else:
                                st.markdown("No suspicious signals detected for this URL.")

            # ------------------------------------------------------------------
            # TASK 4.4 — OVERALL SAFETY ASSESSMENT (RISK SYNTHESIS)
            # ------------------------------------------------------------------
            st.divider()
            st.subheader("🛡️ Overall Safety Assessment")

            overall_state = synthesis_result["state"]
            reason = synthesis_result["reason"]

            state_styles = {
                "SCAM":                {"emoji": "🚨", "color_fn": st.error},
                "SPAM":                {"emoji": "⚠️", "color_fn": st.warning},
                "UNCERTAIN":           {"emoji": "❓", "color_fn": st.info},
                "NO THREAT DETECTED":  {"emoji": "✅", "color_fn": st.success},
            }
            style = state_styles.get(overall_state, {"emoji": "⚪", "color_fn": st.info})
            style["color_fn"](f"### {style['emoji']} Overall Assessment: **{overall_state}**\n\n{reason}")

            # Evidence summary breakdown
            with st.expander("🔍 Synthesized Evidence Summary", expanded=True):
                st.markdown(f"- **SMS Model Prediction:** `{prediction}` ({confidence:.2f}% confidence, Task 3 Risk: `{risk_level}`)")
                if nnz is not None:
                    st.markdown(f"- **Recognized Vocabulary Terms (TF-IDF):** `{nnz}` non-zero token(s)")
                if urls:
                    st.markdown(f"- **URLs Analyzed:** {len(urls)} link(s)")
                    for u_res in url_results:
                        st.markdown(f"  - `{u_res['url']}`: **{u_res['verdict'] or 'N/A'}** (exit code {u_res['exit_code']})")
                else:
                    st.markdown("- **URLs Analyzed:** None present")

            # ------------------------------------------------------------------
            # TASK 4.5 — WHY DID THE ANALYZER MAKE THIS DECISION?
            # ------------------------------------------------------------------
            st.divider()
            st.subheader("💡 Why did the analyzer make this decision?")

            # 1. Message indicators (Rule-based from Task 3)
            st.markdown("#### 📋 Message indicators (Rule-based)")
            if indicators:
                for ind in indicators:
                    st.markdown(f"- ⚠️ {ind}")
            else:
                st.markdown("- None detected (no rule-based trigger phrases matched)")

            # 2. Model explanation (Learned TF-IDF + Logistic Regression weights)
            st.markdown("#### 🧠 Model explanation (Learned feature weights)")

            if not explanation_result["has_features"]:
                st.info(
                    "ℹ️ **No recognized vocabulary tokens**: "
                    f"{explanation_result['summary']}"
                )
            else:
                col_exp1, col_exp2 = st.columns(2)
                with col_exp1:
                    st.markdown("**Tokens pushing toward SPAM (🚨):**")
                    if explanation_result["spam_features"]:
                        for sf in explanation_result["spam_features"]:
                            st.markdown(
                                f"- `{sf['token']}` — pushed toward SPAM "
                                f"(impact: `+{sf['contribution']:.3f}`)"
                            )
                    else:
                        st.markdown("- None detected")

                with col_exp2:
                    st.markdown("**Tokens pushing toward NOT SPAM (✅):**")
                    if explanation_result["ham_features"]:
                        for hf in explanation_result["ham_features"]:
                            st.markdown(
                                f"- `{hf['token']}` — pushed toward NOT SPAM "
                                f"(impact: `{hf['contribution']:.3f}`)"
                            )
                    else:
                        st.markdown("- None detected")

            # 3. Explanation summary
            st.markdown("#### 📝 Explanation summary")
            st.caption(f"**Evidence summary:** {explanation_result['summary']}")

            # ------------------------------------------------------------------
            # TASK 4.6 — WHAT SHOULD I DO? (SAFETY GUIDANCE)
            # ------------------------------------------------------------------
            st.divider()
            st.subheader("🛡️ What should I do?")

            safety_guidance = get_safety_guidance(overall_state, t3_result, url_results)
            for act in safety_guidance["actions"]:
                st.markdown(f"- {act}")

            # ------------------------------------------------------------------
            # TASK 4.6 — OFFICIAL REPORTING & VERIFICATION (TRAI / DoT / MHA)
            # ------------------------------------------------------------------
            st.divider()
            st.subheader("🏛️ Official Reporting & Verification")
            st.caption("Verified primary Government of India telecom and cybercrime reporting channels.")

            if sender_id_input.strip():
                s_id = sender_id_input.strip().upper()
                st.info(
                    f"**Sender ID Guidance for `{s_id}`:**  \n\n"
                    "• **Official Format:** In India, legitimate commercial and transactional SMS headers follow the format **`XY-ABCDEF`** "
                    "(where `X` denotes the telecom operator, `Y` denotes the service circle, and `ABCDEF` represents the registered organization).  \n"
                    "• **Important Red Flag:** Legitimate banks and government departments do not send official transactional or alert SMS from personal 10-digit mobile numbers.  \n"
                    f"• **Verify Ownership:** Look up whether `{s_id}` is an officially registered Principal Entity on the [TRAI Header Information Portal](https://smsheader.trai.gov.in)."
                )

            with st.expander("📌 Official Government Portals & Helplines (TRAI, DoT, MHA)", expanded=True):
                for rep in get_official_reporting_info():
                    st.markdown(
                        f"**{rep['agency']} — [{rep['portal']}]({rep['url']})**  \n"
                        f"- *Purpose:* {rep['purpose']}  \n"
                        f"- *Recommended Action:* {rep['action']}"
                    )

# ---------------------------------------------------------------------------
# FOOTER
# ---------------------------------------------------------------------------
st.divider()
st.caption(
    "🔒 Privacy: All analysis is performed locally. "
    "No SMS data is sent to any external API or server."
)
