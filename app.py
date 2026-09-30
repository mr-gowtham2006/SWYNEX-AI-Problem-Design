"""
AI SMS Safety Analyzer — SWYNEX Technologies AI Internship
Task 4: Final AI Application

app.py — Streamlit application entry point

TASK 4.1: Application skeleton and UI layout.
TASK 4.2: Integrated Task 3 analyze_message() engine.
TASK 4.3: Local URL analysis via barb-phish CLI.
TASK 4.4: Risk synthesis and uncertainty logic.
TASK 4.5: Explainability / feature influence.
TASK 4.6: Safety guidance + official TRAI/DoT/MHA reporting.
UI REDESIGN: Compact two-column layout, tabbed drill-down, dark cybersecurity theme.
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


def defang_url(url: str) -> str:
    """
    Defang a URL so it cannot be accidentally clicked or resolved.
    Replaces schemes and dots in the domain to prevent clickable hyperlinks.
    """
    url = re.sub(r"^https://", "hxxps[://]", url)
    url = re.sub(r"^http://", "hxxp[://]", url)
    url = re.sub(r"^www\.", "www[.]", url)
    return url


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


# ===========================================================================
# UI — only executed when running under the Streamlit server.
# Tests import this file to access logic functions at module level;
# wrapping everything in _run_ui() prevents MagicMock unpacking errors.
# ===========================================================================

def _run_ui():
    """Render the full Streamlit application UI."""

    # =========================================================================
    # PAGE CONFIG
    # =========================================================================
    st.set_page_config(
        page_title="AI SMS Safety Analyzer",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    # =========================================================================
    # GLOBAL STYLE INJECTION
    # Minimal, targeted CSS — no brittle internal Streamlit class selectors.
    # =========================================================================
    st.markdown("""
<style>
/* ── Verdict hero badge pills ─────────────────────────────── */
.verdict-scam {
    display: inline-block;
    background: rgba(239,68,68,0.15);
    color: #EF4444;
    border: 1px solid rgba(239,68,68,0.35);
    padding: 6px 18px;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: 0.04em;
}
.verdict-spam {
    display: inline-block;
    background: rgba(245,158,11,0.15);
    color: #F59E0B;
    border: 1px solid rgba(245,158,11,0.35);
    padding: 6px 18px;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: 0.04em;
}
.verdict-uncertain {
    display: inline-block;
    background: rgba(139,92,246,0.15);
    color: #8B5CF6;
    border: 1px solid rgba(139,92,246,0.35);
    padding: 6px 18px;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: 0.04em;
}
.verdict-safe {
    display: inline-block;
    background: rgba(16,185,129,0.15);
    color: #10B981;
    border: 1px solid rgba(16,185,129,0.35);
    padding: 6px 18px;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: 0.04em;
}
/* ── Token influence chips ────────────────────────────────── */
.token-spam {
    display: inline-block;
    background: rgba(239,68,68,0.12);
    color: #FCA5A5;
    border: 1px solid rgba(239,68,68,0.25);
    padding: 3px 10px;
    border-radius: 6px;
    font-family: 'Consolas','Courier New',monospace;
    font-size: 0.82rem;
    margin: 2px 3px;
}
.token-ham {
    display: inline-block;
    background: rgba(16,185,129,0.12);
    color: #6EE7B7;
    border: 1px solid rgba(16,185,129,0.25);
    padding: 3px 10px;
    border-radius: 6px;
    font-family: 'Consolas','Courier New',monospace;
    font-size: 0.82rem;
    margin: 2px 3px;
}
/* ── Defanged URL display ─────────────────────────────────── */
.defanged-url {
    display: block;
    font-family: 'Consolas','Courier New',monospace;
    background: rgba(15,23,42,0.9);
    color: #38BDF8;
    border: 1px solid #1E3A5F;
    padding: 6px 12px;
    border-radius: 5px;
    font-size: 0.85rem;
    word-break: break-all;
    margin: 6px 0;
}
/* ── Eyebrow section label ────────────────────────────────── */
.eyebrow {
    font-size: 0.70rem;
    font-weight: 600;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    color: #64748B;
    margin-bottom: 4px;
}
/* ── Privacy badge ────────────────────────────────────────── */
.privacy-badge {
    display: inline-block;
    background: rgba(59,130,246,0.12);
    color: #60A5FA;
    border: 1px solid rgba(59,130,246,0.25);
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 600;
}
/* ── Guidance list items ──────────────────────────────────── */
.guidance-item {
    padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    font-size: 0.9rem;
    line-height: 1.55;
}
.guidance-item:last-child { border-bottom: none; }
</style>
""", unsafe_allow_html=True)

    # =========================================================================
    # HEADER
    # =========================================================================
    hdr_left, hdr_right = st.columns([6, 2])
    with hdr_left:
        st.markdown(
            '<p style="font-size:1.55rem;font-weight:700;color:#F8FAFC;margin-bottom:0;line-height:1.2">'
            '🛡️ AI SMS Safety Analyzer</p>'
            '<p style="font-size:0.82rem;color:#64748B;margin-top:2px">'
            'SWYNEX Technologies &middot; AI Internship &middot; Task 4 '
            '&mdash; Scam &amp; Phishing Triage Engine</p>',
            unsafe_allow_html=True,
        )
    with hdr_right:
        st.markdown(
            '<div style="text-align:right;padding-top:10px">'
            '<span class="privacy-badge">🔒 Local AI &middot; No Data Sent Externally</span>'
            '</div>',
            unsafe_allow_html=True,
        )

    if not _MODEL_LOADED:
        st.error(
            "**Analysis engine could not be loaded.**  \n"
            "Make sure `task-2/spam_classifier.pkl` exists relative to `app.py`.  \n"
            f"Details: {_MODEL_ERROR}",
            icon="🚨",
        )

    st.divider()

    # =========================================================================
    # SAMPLE PRESETS
    # =========================================================================
    _PRESETS = {
        "None": "",
        "🏦 SBI KYC Scam": (
            "Dear Customer, Your SBI account will be blocked. "
            "Update KYC immediately: http://sbi-kyc-update.fake-portal.com"
        ),
        "🎰 Lottery Spam": (
            "WINNER! You have won Rs.50,000 in our lucky draw. "
            "Claim FREE prize now, call 9876543210 immediately. Offer expires today!"
        ),
        "💡 Electricity Scam": (
            "URGENT: Your electricity connection will be disconnected tonight at 9 PM. "
            "Pay Rs.800 immediately. Call 8765432190 to avoid disconnection."
        ),
        "✅ OTP (Clean)": (
            "Your OTP for SBI NetBanking login is 482917. "
            "Valid for 10 minutes. Do not share with anyone."
        ),
    }

    # =========================================================================
    # MAIN TWO-COLUMN LAYOUT
    # =========================================================================
    col_input, col_result = st.columns([5, 6], gap="large")

    # ─────────────────────────────────────────────────────────────────────────
    # LEFT COLUMN — INPUT
    # ─────────────────────────────────────────────────────────────────────────
    with col_input:
        with st.container(border=True):
            st.markdown('<p class="eyebrow">📨 Message Under Analysis</p>', unsafe_allow_html=True)

            # Quick-fill presets
            preset_choice = st.pills(
                "Quick test presets",
                options=list(_PRESETS.keys()),
                default="None",
                label_visibility="collapsed",
            )
            preset_text = _PRESETS.get(preset_choice, "")

            sms_input = st.text_area(
                label="SMS Message",
                value=preset_text,
                placeholder="Paste the SMS message you received here\u2026",
                height=130,
                max_chars=5000,
                help="Maximum 5000 characters. Paste the full SMS text you received.",
                label_visibility="collapsed",
            )

            char_count = len(sms_input)
            word_count = len(sms_input.split()) if sms_input.strip() else 0
            st.caption(f"{char_count} / 5000 chars \u00b7 {word_count} words")

            sender_id_input = st.text_input(
                label="Sender ID (optional)",
                placeholder="e.g. VK-HDFCBK, AM-AMAZON, or a 10-digit mobile number",
                help=(
                    "Enter the Sender ID or phone number shown in the SMS. "
                    "Used to provide TRAI header verification guidance."
                ),
            )

            analyze_button = st.button(
                "🔍 Run Full Security Analysis",
                type="primary",
                use_container_width=True,
                disabled=(char_count == 0 or not _MODEL_LOADED),
            )

    # ─────────────────────────────────────────────────────────────────────────
    # RIGHT COLUMN — RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    with col_result:
        if not analyze_button:
            with st.container(border=True):
                st.markdown(
                    '<div style="text-align:center;padding:40px 20px;color:#475569">'
                    '<div style="font-size:2.5rem;margin-bottom:12px">🛡️</div>'
                    '<div style="font-size:1rem;font-weight:600;color:#94A3B8">Waiting for Analysis</div>'
                    '<div style="font-size:0.82rem;margin-top:6px">'
                    'Paste an SMS on the left and click <strong>Run Full Security Analysis</strong>.'
                    '</div></div>',
                    unsafe_allow_html=True,
                )
        else:
            if not sms_input.strip():
                st.error("Please enter an SMS message before analyzing.")
            else:
                with st.spinner("Analyzing — SMS classifier, URL forensics, and risk synthesis running\u2026"):
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

                    # Task 4.6: Safety guidance
                    overall_state = synthesis_result["state"]
                    safety_guidance = get_safety_guidance(overall_state, t3_result, url_results)

                # ── Error path ─────────────────────────────────────────────
                if "error" in t3_result:
                    st.error(f"{t3_result['error']}", icon="🚨")

                # ── Success path ────────────────────────────────────────────
                else:
                    prediction  = t3_result["prediction"]
                    confidence  = t3_result["confidence"]
                    risk_level  = t3_result["risk_level"]
                    indicators  = t3_result["indicators"]
                    reason      = synthesis_result["reason"]

                    # ── Hero Verdict Card ────────────────────────────────────
                    _verdict_css = {
                        "SCAM":               "verdict-scam",
                        "SPAM":               "verdict-spam",
                        "UNCERTAIN":          "verdict-uncertain",
                        "NO THREAT DETECTED": "verdict-safe",
                    }
                    _verdict_icon = {
                        "SCAM":               "🚨",
                        "SPAM":               "⚠️",
                        "UNCERTAIN":          "🔍",
                        "NO THREAT DETECTED": "🛡️",
                    }
                    _verdict_action = {
                        "SCAM":               "⛔ Do NOT click any links or share OTPs.",
                        "SPAM":               "🚫 Block sender — do not reply or click links.",
                        "UNCERTAIN":          "⚠️ Proceed with caution — verify sender independently.",
                        "NO THREAT DETECTED": "✔️ No immediate action required.",
                    }
                    css_cls = _verdict_css.get(overall_state, "verdict-uncertain")
                    icon    = _verdict_icon.get(overall_state, "❓")
                    action  = _verdict_action.get(overall_state, "")

                    with st.container(border=True):
                        st.markdown(
                            f'<span class="{css_cls}">{icon} {overall_state}</span>',
                            unsafe_allow_html=True,
                        )
                        st.markdown(
                            f"<small style='color:#94A3B8'>{reason}</small>",
                            unsafe_allow_html=True,
                        )
                        st.markdown(f"**{action}**")

                    # ── KPI Metric Row ───────────────────────────────────────
                    m1, m2, m3 = st.columns(3, gap="small")
                    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(risk_level, "⚪")
                    with m1:
                        st.metric("SMS Model", prediction)
                    with m2:
                        st.metric("Confidence", f"{confidence:.1f}%")
                    with m3:
                        st.metric("Risk Level", f"{risk_emoji} {risk_level}")

                    # ── Tabbed Deep-Dive ─────────────────────────────────────
                    tab_overview, tab_urls, tab_explain, tab_safety = st.tabs([
                        "📋 Overview",
                        f"🔗 URL Forensics ({len(urls)})",
                        "💡 Explainability",
                        "🛡️ Safety & Reporting",
                    ])

                    # ── TAB 1: OVERVIEW ──────────────────────────────────────
                    with tab_overview:
                        if sender_id_input.strip():
                            s_id = sender_id_input.strip().upper()
                            st.info(
                                f"**Sender ID `{s_id}` — Quick Check**  \n"
                                "Legitimate commercial headers follow the format `XY-ABCDEF`. "
                                "Banks and government agencies do **not** use 10-digit mobile numbers.  \n"
                                f"[Verify on TRAI Header Portal ↗](https://smsheader.trai.gov.in)",
                                icon="🏛️",
                            )

                        with st.container(border=True):
                            st.markdown(
                                '<p class="eyebrow">Synthesized Evidence</p>',
                                unsafe_allow_html=True,
                            )
                            st.markdown(
                                f"- **SMS Classification:** `{prediction}` — {confidence:.1f}% confidence  \n"
                                f"- **Task 3 Risk Level:** `{risk_level}`  \n"
                                f"- **Vocabulary Tokens Matched:** `{nnz if nnz is not None else 'N/A'}` TF-IDF non-zero  \n"
                                f"- **URLs Detected:** `{len(urls)}`"
                            )

                        with st.container(border=True):
                            st.markdown(
                                '<p class="eyebrow">Rule-Based Indicators</p>',
                                unsafe_allow_html=True,
                            )
                            if indicators:
                                for ind in indicators:
                                    st.markdown(f"⚠️ {ind}")
                            else:
                                st.caption("No rule-based trigger phrases matched.")

                    # ── TAB 2: URL FORENSICS ─────────────────────────────────
                    with tab_urls:
                        if not urls:
                            st.info("No URLs were detected in this message.", icon="ℹ️")
                        else:
                            st.caption(
                                f"{len(urls)} URL(s) analyzed locally using **barb-phish** "
                                "(offline heuristics — no data sent externally)."
                            )
                            for ur in url_results:
                                exit_code = ur["exit_code"]
                                verdict   = ur["verdict"] or "UNKNOWN"
                                label, emoji = _BARB_EXIT_LABELS.get(exit_code, ("UNKNOWN", "⚪"))
                                defanged  = defang_url(ur["url"])

                                with st.container(border=True):
                                    st.markdown(
                                        f'<p class="eyebrow">{emoji} {verdict} — URL Forensic Report</p>'
                                        f'<span class="defanged-url">{defanged}</span>',
                                        unsafe_allow_html=True,
                                    )

                                    if ur["error"]:
                                        st.warning(ur["error"])
                                    else:
                                        ua, ub = st.columns(2)
                                        with ua:
                                            st.metric("Verdict", f"{emoji} {verdict}")
                                        with ub:
                                            score_display = (
                                                f"{ur['risk_score']:.1f}"
                                                if ur["risk_score"] is not None
                                                else "N/A"
                                            )
                                            st.metric("Risk Score", score_display)

                                        if ur["signals"]:
                                            with st.expander("🔎 Detected Signals", expanded=False):
                                                for sig in ur["signals"]:
                                                    sev    = sig.get("severity", "")
                                                    lbl    = sig.get("label", "")
                                                    detail = sig.get("detail", "")
                                                    sev_emoji = {
                                                        "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"
                                                    }.get(sev, "⚪")
                                                    st.markdown(f"- {sev_emoji} **{lbl}**: {detail}")
                                        else:
                                            st.caption("No suspicious signals detected for this URL.")

                                        with st.expander("🔧 Technical Telemetry", expanded=False):
                                            st.markdown(
                                                f"- **Exit Code:** `{exit_code}` — {label}  \n"
                                                f"- **Original URL:** `{ur['url']}`"
                                            )
                                            if ur["raw"]:
                                                st.json(ur["raw"])

                    # ── TAB 3: EXPLAINABILITY ────────────────────────────────
                    with tab_explain:
                        st.markdown(
                            "These chips show which vocabulary terms most influenced "
                            "the model's prediction.  \n"
                            "Impact = `TF-IDF weight × logistic regression coefficient`."
                        )

                        if not explanation_result["has_features"]:
                            st.info(
                                f"**No recognized vocabulary tokens:** {explanation_result['summary']}",
                                icon="ℹ️",
                            )
                        else:
                            exp_left, exp_right = st.columns(2, gap="medium")

                            with exp_left:
                                with st.container(border=True):
                                    st.markdown(
                                        '<p class="eyebrow">🚨 Pushes Toward SPAM</p>',
                                        unsafe_allow_html=True,
                                    )
                                    if explanation_result["spam_features"]:
                                        chips = " ".join(
                                            f'<span class="token-spam">'
                                            f'{sf["token"]} <b>+{sf["contribution"]:.3f}</b>'
                                            f'</span>'
                                            for sf in explanation_result["spam_features"]
                                        )
                                        st.markdown(chips, unsafe_allow_html=True)
                                    else:
                                        st.caption("None detected.")

                            with exp_right:
                                with st.container(border=True):
                                    st.markdown(
                                        '<p class="eyebrow">✅ Pushes Toward NOT SPAM</p>',
                                        unsafe_allow_html=True,
                                    )
                                    if explanation_result["ham_features"]:
                                        chips = " ".join(
                                            f'<span class="token-ham">'
                                            f'{hf["token"]} <b>{hf["contribution"]:.3f}</b>'
                                            f'</span>'
                                            for hf in explanation_result["ham_features"]
                                        )
                                        st.markdown(chips, unsafe_allow_html=True)
                                    else:
                                        st.caption("None detected.")

                        st.caption(f"**Evidence summary:** {explanation_result['summary']}")

                    # ── TAB 4: SAFETY & REPORTING ────────────────────────────
                    with tab_safety:
                        with st.container(border=True):
                            st.markdown(
                                '<p class="eyebrow">Recommended Actions</p>',
                                unsafe_allow_html=True,
                            )
                            for act in safety_guidance["actions"]:
                                st.markdown(
                                    f"<div class='guidance-item'>&bull; {act}</div>",
                                    unsafe_allow_html=True,
                                )

                        with st.expander(
                            "🏛️ Official Government Reporting Portals (TRAI · DoT · MHA)",
                            expanded=False,
                        ):
                            st.caption(
                                "Verified primary Government of India telecom and cybercrime reporting channels."
                            )
                            for rep in get_official_reporting_info():
                                st.markdown(
                                    f"**{rep['agency']} — [{rep['portal']}]({rep['url']})**  \n"
                                    f"- *Purpose:* {rep['purpose']}  \n"
                                    f"- *Recommended Action:* {rep['action']}"
                                )
                                st.divider()

    # =========================================================================
    # FOOTER
    # =========================================================================
    st.markdown(
        '<hr style="border-color:rgba(255,255,255,0.07);margin-top:28px"/>'
        '<p style="text-align:center;font-size:0.75rem;color:#475569;margin-top:6px">'
        '🔒 <strong>Privacy First</strong> &middot; All analysis is performed locally on this device. '
        'No SMS content is transmitted to any external API or server. '
        '&nbsp;|&nbsp; AI internship project &middot; SWYNEX Technologies'
        '</p>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# ENTRY POINT — run UI only when Streamlit server is actually executing this
# ---------------------------------------------------------------------------
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx as _get_ctx
    if _get_ctx() is not None:
        _run_ui()
except Exception:
    # Fallback for older Streamlit builds or direct `streamlit run` invocation.
    # Tests never reach here because they stub `streamlit` as a MagicMock
    # and that MagicMock import will raise AttributeError before this point.
    pass
