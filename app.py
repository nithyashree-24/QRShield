import streamlit as st
import cv2
import numpy as np
import re
from urllib.parse import urlparse


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="QRShield",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed"
)


# ==========================================
# QR CONTENT TYPE DETECTOR
# ==========================================

def detect_content_type(data):

    if data.startswith(("http://", "https://", "www.")):
        return "🌐 Web URL"

    if data.startswith("mailto:") or re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        data
    ):
        return "📧 Email Address"

    if data.startswith("tel:") or re.match(
        r"^\+?[0-9\s\-()]{7,}$",
        data
    ):
        return "📞 Phone Number"

    if data.startswith("WIFI:"):
        return "📶 Wi-Fi Configuration"

    return "📝 Plain Text"


# ==========================================
# URL SECURITY ANALYZER
# ==========================================

def analyze_url(url):

    if url.startswith("www."):
        url = "https://" + url

    parsed = urlparse(url)

    risk_score = 0
    findings = []
    score_breakdown = []

    # --------------------------------------
    # 1. HTTPS CHECK
    # --------------------------------------

    if parsed.scheme == "https":

        findings.append(
            "HTTPS is enabled"
        )

    else:

        risk_score += 20

        findings.append(
            "HTTPS is not enabled"
        )

        score_breakdown.append(
            "HTTP / No HTTPS → +20"
        )

    # --------------------------------------
    # 2. IP ADDRESS CHECK
    # --------------------------------------

    hostname = parsed.hostname or ""

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):

        risk_score += 25

        findings.append(
            "URL uses an IP address instead of a domain"
        )

        score_breakdown.append(
            "IP address instead of domain → +25"
        )

    else:

        findings.append(
            "Normal domain format detected"
        )

    # --------------------------------------
    # 3. SUSPICIOUS KEYWORD CHECK
    # --------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "account",
        "update",
        "password",
        "bank",
        "secure"
    ]

    found_words = []

    for word in suspicious_words:

        if word in url.lower():
            found_words.append(word)

    if found_words:

        risk_score += 15

        findings.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

        score_breakdown.append(
            "Suspicious keywords detected → +15"
        )

    else:

        findings.append(
            "No common suspicious keywords detected"
        )

    # --------------------------------------
    # 4. URL SHORTENER CHECK
    # --------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]

    if hostname.lower() in shorteners:

        risk_score += 20

        findings.append(
            "URL shortener detected"
        )

        score_breakdown.append(
            "URL shortener detected → +20"
        )

    else:

        findings.append(
            "No known URL shortener detected"
        )

    # --------------------------------------
    # 5. @ SYMBOL CHECK
    # --------------------------------------

    if "@" in url:

        risk_score += 20

        findings.append(
            "URL contains @ symbol"
        )

        score_breakdown.append(
            "@ symbol detected → +20"
        )

    else:

        findings.append(
            "No @ symbol detected"
        )

    # --------------------------------------
    # LIMIT SCORE
    # --------------------------------------

    risk_score = min(risk_score, 100)

    # --------------------------------------
    # RISK LEVEL
    # --------------------------------------

    if risk_score >= 60:

        risk_level = "HIGH RISK"

    elif risk_score >= 30:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "LOW RISK"

    return (
        risk_score,
        risk_level,
        findings,
        score_breakdown
    )


# ==========================================
# SECURITY RECOMMENDATION
# ==========================================

def get_recommendation(risk_level):

    if risk_level == "HIGH RISK":

        return (
            "🚨 Avoid opening this URL. "
            "Do not enter passwords, banking details, "
            "or other sensitive information. "
            "Verify the QR code source before accessing it."
        )

    elif risk_level == "MEDIUM RISK":

        return (
            "⚠️ Use caution with this URL. "
            "Verify the website and QR code source "
            "before entering any sensitive information."
        )

    else:

        return (
            "✅ No major rule-based risk indicators "
            "were detected. Still verify the source "
            "before opening the URL."
        )


# ==========================================
# RISK SUMMARY
# ==========================================

def get_risk_summary(risk_score):

    if risk_score >= 60:

        return (
            "Multiple suspicious indicators were detected. "
            "The QR code should be treated with high caution."
        )

    elif risk_score >= 30:

        return (
            "Some potentially suspicious indicators were "
            "detected. Verify the QR code source carefully."
        )

    else:

        return (
            "No major rule-based risk indicators were "
            "detected in the scanned URL."
        )


# ==========================================
# SESSION HISTORY
# ==========================================

if "scan_history" not in st.session_state:

    st.session_state.scan_history = []


# ==========================================
# HEADER
# ==========================================

st.title("🔐 QRShield")

st.markdown(
    "**QR Code Security & Risk Analyzer**"
)

st.write(
    "Analyze QR codes, identify their content type, "
    "and detect common URL-based security risk indicators."
)

st.divider()


# ==========================================
# PROJECT FEATURES
# ==========================================
col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "🔍 QR Detection",
        "OpenCV"
    )

with col2:

    st.metric(
        "🛡️ Risk Analysis",
        "Rule-Based"
    )

with col3:

    st.metric(
        "📋 Scan History",
        "Session"
    )

st.divider()


# ==========================================
# UPLOAD SECTION
# ==========================================

st.subheader(
    "📤 Upload QR Code"
)

uploaded_file = st.file_uploader(
    "Choose a QR code image",
    type=["png", "jpg", "jpeg"],
    help="Upload a clear PNG, JPG, or JPEG QR code image."
)


# ==========================================
# PROCESS QR CODE
# ==========================================

if uploaded_file is not None:

    st.success(
        "QR Code image uploaded successfully!"
    )

    st.image(
        uploaded_file,
        caption="Uploaded QR Code",
        width="stretch"
    )

    st.write("")

    # ======================================
    # SCAN BUTTON
    # ======================================

    if st.button(
        "🔍 Scan QR Code",
        use_container_width=True
    ):

        # ----------------------------------
        # READ IMAGE
        # ----------------------------------

        image_bytes = uploaded_file.getvalue()

        image_array = cv2.imdecode(
            np.frombuffer(
                image_bytes,
                dtype=np.uint8
            ),
            cv2.IMREAD_COLOR
        )

        # ----------------------------------
        # QR DETECTOR
        # ----------------------------------

        detector = cv2.QRCodeDetector()

        data, points, _ = detector.detectAndDecode(
            image_array
        )

        # ==================================
        # QR DETECTED
        # ==================================

        if data:

            st.success(
                "✅ QR Code detected successfully!"
            )

            st.divider()

            # ----------------------------------
            # QR CONTENT
            # ----------------------------------

            st.subheader(
                "📄 QR Content"
            )

            st.code(
                data,
                language=None
            )

            # ----------------------------------
            # CONTENT TYPE
            # ----------------------------------

            content_type = detect_content_type(
                data
            )

            st.subheader(
                "📌 Content Type"
            )

            st.info(
                content_type
            )

            # ==================================
            # URL ANALYSIS
            # ==================================

            is_url = data.startswith(
                (
                    "http://",
                    "https://",
                    "www."
                )
            )

            if is_url:

                (
                    risk_score,
                    risk_level,
                    findings,
                    score_breakdown
                ) = analyze_url(data)

                # ----------------------------------
                # SECURITY ANALYSIS
                # ----------------------------------

                st.divider()

                st.subheader(
                    "🛡️ Security Analysis"
                )

                metric_col1, metric_col2 = st.columns(2)

                with metric_col1:

                    st.metric(
                        "Risk Score",
                        f"{risk_score}/100"
                    )

                with metric_col2:

                    st.metric(
                        "Risk Level",
                        risk_level
                    )

                # ----------------------------------
                # PROGRESS
                # ----------------------------------

                st.progress(
                    risk_score / 100
                )

                # ----------------------------------
                # RISK LEVEL MESSAGE
                # ----------------------------------

                if risk_level == "HIGH RISK":

                    st.error(
                        "🔴 HIGH RISK"
                    )

                elif risk_level == "MEDIUM RISK":

                    st.warning(
                        "🟡 MEDIUM RISK"
                    )

                else:

                    st.success(
                        "🟢 LOW RISK"
                    )

                # ----------------------------------
                # RISK SUMMARY
                # ----------------------------------

                st.subheader(
                    "📊 Risk Summary"
                )

                st.write(
                    get_risk_summary(
                        risk_score
                    )
                )

                # ----------------------------------
                # SCORE BREAKDOWN
                # ----------------------------------

                st.subheader(
                    "📊 Risk Score Breakdown"
                )

                if score_breakdown:

                    for item in score_breakdown:

                        st.write(
                            "• " + item
                        )

                else:

                    st.write(
                        "• No risk factors detected → +0"
                    )

                # ----------------------------------
                # SECURITY FINDINGS
                # ----------------------------------

                st.subheader(
                    "🔍 Security Findings"
                )

                for finding in findings:

                    st.write(
                        "• " + finding
                    )

                # ----------------------------------
                # SECURITY RECOMMENDATION
                # ----------------------------------

                st.subheader(
                    "🛡️ Security Recommendation"
                )

                recommendation = get_recommendation(
                    risk_level
                )

                if risk_level == "HIGH RISK":

                    st.error(
                        recommendation
                    )

                elif risk_level == "MEDIUM RISK":

                    st.warning(
                        recommendation
                    )

                else:

                    st.success(
                        recommendation
                    )

                # ==================================
                # ADD TO HISTORY
                # ==================================

                history_item = {
                    "content": data,
                    "type": content_type,
                    "risk": risk_score,
                    "level": risk_level
                }

                st.session_state.scan_history.append(
                    history_item
                )

            else:

                # ==================================
                # NON-URL CONTENT
                # ==================================

                st.divider()

                st.info(
                    "ℹ️ This QR code does not contain "
                    "a web URL, so URL-based security "
                    "analysis was not performed."
                )

                st.subheader(
                    "🛡️ Security Recommendation"
                )

                st.info(
                    "Review the QR content carefully "
                    "and verify its source before using it."
                )

                # ----------------------------------
                # HISTORY
                # ----------------------------------

                history_item = {
                    "content": data,
                    "type": content_type,
                    "risk": 0,
                    "level": "NOT ANALYZED"
                }

                st.session_state.scan_history.append(
                    history_item
                )

        else:

            st.error(
                "❌ Could not detect a QR code. "
                "Please upload a clear QR code image."
            )


# ==========================================
# SCAN HISTORY
# ==========================================

if st.session_state.scan_history:

    st.divider()

    st.subheader(
        "📋 Scan History"
    )

    st.caption(
        "Previous scans from the current session"
    )

    for index, item in enumerate(
        reversed(
            st.session_state.scan_history
        ),
        start=1
    ):

        with st.expander(
            f"Scan {index} — "
            f"{item['level']}"
        ):

            st.write(
                f"**Content Type:** {item['type']}"
            )

            st.write(
                "**QR Content:**"
            )

            st.code(
                item["content"],
                language=None
            )

            if item["level"] == "HIGH RISK":

                st.error(
                    f"Risk Score: {item['risk']}/100 — "
                    f"HIGH RISK"
                )

            elif item["level"] == "MEDIUM RISK":

                st.warning(
                    f"Risk Score: {item['risk']}/100 — "
                    f"MEDIUM RISK"
                )

            elif item["level"] == "LOW RISK":

                st.success(
                    f"Risk Score: {item['risk']}/100 — "
                    f"LOW RISK"
                )

            else:

                st.info(
                    "Risk analysis not performed"
                )


# ==========================================
# CLEAR HISTORY
# ==========================================

if st.session_state.scan_history:

    st.divider()

    if st.button(
        "🗑️ Clear Scan History",
        use_container_width=True
    ):

        st.session_state.scan_history = []

        st.rerun()


# ==========================================
# SECURITY NOTE
# ==========================================

st.divider()

st.info(
    "🔒 **Security Note:** QRShield uses "
    "rule-based analysis to identify common "
    "URL risk indicators. A low-risk result "
    "does not guarantee that a URL is completely safe."
)


# ==========================================
# FOOTER
# ==========================================

st.markdown(
    "---"
)

st.caption(
    "QRShield • QR Code Security & Risk Analyzer"
)

st.caption(
    "Built with Python • OpenCV • Streamlit"
)