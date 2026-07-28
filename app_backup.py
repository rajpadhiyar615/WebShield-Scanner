import streamlit as st
import os

url = None
from scanners.info import get_website_info
from scanners.tech import detect_technology
from scanners.headers import check_headers
from scanners.sslscan import scan_ssl
from scanners.cookies import scan_cookies
from scanners.methods import scan_http_methods
from scanners.robots import scan_robots
from scanners.sitemap import scan_sitemap
from scanners.xss import scan_xss
from scanners.sqli import scan_sql
from scanners.cors import scan_cors

from scanner import calculate_score
from professional_report import generate_professional_report
from dashboard import show_dashboard
from owasp import get_owasp_details
from cvss import calculate_cvss
from recommendations import get_recommendation
from scanners.misconfiguration import scan_misconfiguration
from scanners.directory import scan_directory_listing
from scanners.redirect import scan_open_redirect
from scanners.disclosure import scan_information_disclosure
from scanners.ssrf import scan_ssrf
from admin import show_admin_panel
from database import (
    create_database,
    save_scan,
    get_history,
    delete_scan,
    clear_history,
    get_previous_scan,
)
from auth import create_users_table, login_user
from utils import safe_scan

# Initialize Database
create_database()
create_users_table()


# =====================================
# Page Configuration
# =====================================

st.set_page_config(page_title="WebShield Scanner", page_icon="🛡️", layout="wide")

if "logged_in" not in st.session_state:

    st.session_state.logged_in = False


if not st.session_state.logged_in:

    st.title("🔐 WebShield Login")

    username = st.text_input("Username")

    password = st.text_input("Password", type="password")

    if st.button("Login"):

        user = login_user(username, password)

        if user:

            st.session_state.logged_in = True

            st.session_state.username = user[1]

            st.session_state.role = user[3]

            st.success("Login Successful")

            st.rerun()

        else:

            st.error("Invalid Credentials")

    st.stop()


# =====================================
# Sidebar
# =====================================

st.sidebar.title("🛡 WebShield Scanner")
st.sidebar.write(f"Welcome {st.session_state.username}")


if st.sidebar.button("Logout"):

    st.session_state.logged_in = False

    st.session_state.username = None

    st.session_state.role = None

    st.rerun()

menu = ["Scanner", "Dashboard", "Scan History"]


if st.session_state.role == "admin":

    menu.append("Admin Panel")


page = st.sidebar.radio("Navigation", menu)


st.sidebar.markdown("---")

st.sidebar.write("Version")
st.sidebar.success("1.0")


st.sidebar.write("Developer")
st.sidebar.info("Raj Padhiyar")


st.sidebar.write("Project")
st.sidebar.write("Final Year Capstone Project")


# =====================================
# Scanner Page
# =====================================

if page == "Scanner":

    st.title("🛡️ WebShield Scanner")

    st.subheader("Python Based Website Vulnerability Scanner")

    url = st.text_input("Enter Website URL", placeholder="https://example.com")

    if st.button("🚀 Start Scan"):

        # Check URL
        if not url:

            st.warning("Please enter website URL")

            st.stop()

        # Get previous scan
        previous_scan = get_previous_scan(url)

        old_score = None
        old_severity = None

        if previous_scan:

            old_score = previous_scan[2]

            old_severity = previous_scan[3]

            st.info(f"""
Previous Scan Found

Previous Score: {old_score}/100

Previous Risk: {old_severity}
""")

        # Progress Bar
        progress = st.progress(0)

        progress.progress(10)
        # =====================================
        # Website Information
        # =====================================

        st.header("🌐 Website Information")

        info = safe_scan(get_website_info, url)

        if isinstance(info, dict) and "Error" in info:
            st.error(info["Error"])
        else:
            if isinstance(info, dict):
                for key, value in info.items():
                    st.write(f"**{key}:** {value}")

        # =====================================
        # Technology Detection
        # =====================================

        progress.progress(20)

        st.header("🛠 Technology Stack")

        tech = safe_scan(detect_technology, url)

        if isinstance(tech, dict):
            for key, value in tech.items():

                if isinstance(value, list):
                    value = ", ".join(value)

                st.write(f"**{key}:** {value}")

        # =====================================
        # Security Headers
        # =====================================

        progress.progress(35)

        st.header("🛡 Security Headers")

        headers = safe_scan(check_headers, url)

        if isinstance(headers, dict):
            for key, value in headers.items():

                if value == "Missing":
                    st.error(f"{key}: Missing ❌")
                else:
                    st.success(f"{key}: {value}")

        # =====================================
        # SSL Scan
        # =====================================

        progress.progress(50)

        st.header("🔒 SSL/TLS Information")

        ssl_info = safe_scan(scan_ssl, url)

        if isinstance(ssl_info, dict):
            for key, value in ssl_info.items():
                st.write(f"**{key}:** {value}")

        # =====================================
        # Cookie Scan
        # =====================================

        progress.progress(65)

        st.header("🍪 Cookie Security")

        cookies = safe_scan(scan_cookies, url)

        if isinstance(cookies, list):

            for cookie in cookies:

                st.write(f"""
Secure: {'✅' if cookie.get('Secure') else '❌'}

HttpOnly: {'✅' if cookie.get('HttpOnly') else '❌'}

SameSite: {cookie.get('SameSite')}
""")

        else:
            st.info("No cookies detected")

            # =====================================
        # HTTP Methods
        # =====================================

        progress.progress(75)

        st.header("🌐 HTTP Methods")

        methods = safe_scan(scan_http_methods, url)

        if isinstance(methods, list):
            for method in methods:

                if method in ["PUT", "DELETE", "TRACE"]:
                    st.error(f"{method} Dangerous ❌")
                else:
                    st.success(f"{method} Allowed ✅")

        # =====================================
        # OWASP Vulnerability Scan
        # =====================================

        progress.progress(85)

        st.header("🔥 OWASP Vulnerability Scan")

        xss = safe_scan(scan_xss, url)
        sql = safe_scan(scan_sql, url)
        cors = safe_scan(scan_cors, url)
        misconfig = safe_scan(scan_misconfiguration, url)
        directory = safe_scan(scan_directory_listing, url)
        redirect = safe_scan(scan_open_redirect, url)
        disclosure = safe_scan(scan_information_disclosure, url)
        ssrf = safe_scan(scan_ssrf, url)

        vulnerabilities = [
            xss,
            sql,
            cors,
            misconfig,
            directory,
            redirect,
            disclosure,
            ssrf,
        ]

        for vuln in vulnerabilities:

            if not isinstance(vuln, dict):
                continue

            if "Vulnerability" not in vuln:
                continue

            vulnerability_name = vuln.get("Vulnerability", "Unknown")

            details = get_owasp_details(vulnerability_name)

            cvss = calculate_cvss(vulnerability_name)

            recommendation = get_recommendation(vulnerability_name)

            status = vuln.get("Status", "Unknown")

            severity = details.get("severity", "Unknown")

            severity_badge = {
                "Critical": "🔴 Critical",
                "High": "🟠 High",
                "Medium": "🟡 Medium",
                "Low": "🟢 Low",
            }

            severity_display = severity_badge.get(severity, "⚪ Unknown")

            owasp_category = details.get("category", "Unknown")

            cwe = details.get("cwe", "Unknown")

            cvss_score = cvss.get("CVSS Score", "N/A")

            risk = cvss.get("Risk", "Unknown")

            impact = recommendation.get("Impact", "No impact information")

            fixes = recommendation.get("Fixes", [])

            if status in ["Vulnerable", "Detected", "Potentially Vulnerable"]:

                st.error(f"""
🚨 Vulnerability: {vulnerability_name}

OWASP Category: {owasp_category}

CWE: {cwe}

Severity: {severity_display}

Status: {status}

CVSS Score: {cvss_score}

Risk: {risk}

Impact: {impact}

Recommended Fix:
{", ".join(fixes)}
""")

            else:

                st.success(f"""
✅ Vulnerability: {vulnerability_name}

OWASP Category: {owasp_category}

Severity: {severity_display}

Status: {status}
""")

            # =====================================
        # Security Score
        # =====================================

        progress.progress(90)

score = calculate_score(headers, ssl_info, cookies, methods)

st.header("📊 Security Score")
st.metric("Security Score", f"{score}/100")

if score >= 90:
    severity = "Low Risk"
elif score >= 70:
    severity = "Medium Risk"
else:
    severity = "High Risk"

st.info(f"Risk Level: {severity}")


# =====================================
# Risk Level
# =====================================

if score >= 90:
    severity = "Low Risk"

elif score >= 70:
    severity = "Medium Risk"
else:
    severity = "High Risk"

st.info(f"Risk Level: {severity}")

# =====================================
# robots.txt
# =====================================

st.header("🤖 robots.txt")

robots = safe_scan(scan_robots, url)

st.write(robots)

# =====================================
# sitemap.xml
# =====================================

st.header("🗺 sitemap.xml")

sitemap = safe_scan(scan_sitemap, url)

st.write(sitemap)

# =====================================
# Save Scan
# =====================================

save_scan(url, score, severity, vulnerabilities)

# =====================================
# Scan Comparison
# =====================================

if previous_scan and old_score is not None:

    score_difference = score - old_score

    st.header("📈 Scan Comparison")

    if score_difference > 0:

        st.success(f"""
Security Improved ✅

Previous Score:
{old_score}/100

Current Score:
{score}/100

Increase:
+{score_difference} points
""")

    elif score_difference < 0:

        st.error(f"""
Security Decreased ⚠️

Previous Score:
{old_score}/100

Current Score:
{score}/100

Decrease:
{abs(score_difference)} points
""")

    else:

        st.info("Security score unchanged")

    st.write(f"""
Previous Risk:
{old_severity}

Current Risk:
{severity}
""")

# =====================================
# PDF Report
# =====================================

cvss_results = []

recommendation_results = []


for vuln in vulnerabilities:

    if isinstance(vuln, dict) and "Vulnerability" in vuln:

        cvss_results.append(calculate_cvss(vuln["Vulnerability"]))

        recommendation_results.append(get_recommendation(vuln["Vulnerability"]))


report_data = {
    "Website Information": info,
    "Technology Stack": tech,
    "Security Headers": headers,
    "SSL Information": ssl_info,
    "Cookies": cookies,
    "HTTP Methods": methods,
    "OWASP Vulnerabilities": {
        "Findings": vulnerabilities,
        "CVSS Assessment": cvss_results,
        "Recommendations": recommendation_results,
    },
    "Security Score": {"Score": score, "Severity": severity},
}


report_file = "WebShield_Security_Report.pdf"


try:

    generate_professional_report(report_file, report_data)

    st.success("✅ PDF Report Generated")

    with open(report_file, "rb") as pdf:

        pdf_data = pdf.read()

    st.download_button(
        label="📄 Download Security Report",
        data=pdf_data,
        file_name=report_file,
        mime="application/pdf",
    )


except Exception as e:

    st.error(f"PDF Generation Error: {e}")

# =====================================
# Dashboard Page
# =====================================

if page == "Dashboard":

    show_dashboard()

# =====================================
# Scan History Page
# =====================================

elif page == "Scan History":

    st.title("📜 Scan History")

    history = get_history()

    if len(history) == 0:

        st.info("No previous scans found")

    else:

        for scan in history:

            st.write(f"""
🌐 Website:
{scan[1]}


📊 Score:
{scan[2]}/100


⚠️ Severity:
{scan[3]}


📅 Date:
{scan[5]}


-----------------------------
""")


# =====================================
# Admin Panel
# =====================================

elif page == "Admin Panel":

    if st.session_state.role == "admin":

        show_admin_panel()

    else:

        st.error("Access Denied")
