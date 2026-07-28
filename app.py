import streamlit as st
import json
import uuid

# ==========================
# Scanner Modules
# ==========================

from style import load_css
from scanners.info import get_website_info
from scanners.tech import detect_technology
from scanners.headers import check_headers
from scanners.sslscan import scan_ssl
from scanners.cookies import scan_cookies
from scanners.methods import scan_http_methods
from scanners.robots import scan_robots
from scanners.xss import scan_xss
from scanners.sqli import scan_sql
from scanners.cors import scan_cors
from scanners.misconfiguration import scan_misconfiguration
from scanners.directory import scan_directory_listing
from scanners.redirect import scan_open_redirect
from scanners.disclosure import scan_information_disclosure
from scanners.ssrf import scan_ssrf
from scanners.portscan import scan_ports
from scanners.dns_scan import scan_dns
from scanners.subdomain import scan_subdomains
from owasp import get_owasp_details

from comparison import compare_scan
from severity import calculate_severity
from cve.nvd import search_cve
from export import export_csv, export_excel
from owasp_mapping import get_owasp_category
from recommendations_ai import generate_recommendation

# ==========================
# Project Modules
# ==========================

from scanner import calculate_score
from professional_report import generate_professional_report
from dashboard import show_dashboard
from cvss import calculate_cvss
from vulnerability.engine import analyze_vulnerability
from admin import show_admin_panel
from utils import safe_scan

from database import (
    create_database,
    save_scan,
    get_history,
    get_previous_scan,
    delete_scan,
    clear_history,
)

from auth import (
    create_users_table,
    login_user,
    register_user,
)

# ==========================
# Professional UI Card
# ==========================


def metric_card(title, value, icon):

    st.markdown(
        f"""
        <div class="card">

            <h3>
                {icon} {title}
            </h3>

            <h1>
                {value}
            </h1>

        </div>
        """,
        unsafe_allow_html=True,
    )


raw_vulnerabilities = []
vulnerabilities = []
# ==========================
# Initialize Database
# ==========================

create_database()
create_users_table()

# ==========================
# Page Configuration
# ==========================

st.set_page_config(
    page_title="WebShield Scanner",
    page_icon="🛡️",
    layout="wide",
)
load_css()
# ==========================
# Session State
# ==========================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "role" not in st.session_state:
    st.session_state.role = "user"

# ==========================
# Login / Register
# ==========================

if not st.session_state.logged_in:

    st.title("🔐 WebShield Login")

    login_tab, register_tab = st.tabs(["Login", "Register"])

    # --------------------------
    # Login
    # --------------------------

    with login_tab:

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

                st.error("Invalid Username or Password")

    # --------------------------
    # Register
    # --------------------------

    with register_tab:

        st.subheader("Create New Account")

        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")

        if st.button("Register"):

            if register_user(new_username, new_password):

                st.success("Account Created Successfully. Please Login.")

            else:

                st.error("Username already exists")

    st.stop()


# ==========================
# Sidebar Navigation
# ==========================

with st.sidebar:

    st.markdown(
        """
        <h1>
        🛡 WebShield
        </h1>

        <p>
        Security Scanner
        </p>

        """,
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation", ["🚀 Scanner", "📊 Dashboard", "📜 History", "⚙ Admin"]
    )

    st.markdown(
        """
        ---
        
        👨‍💻 Developer  
        Raj Padhiyar  

        Version 2.0

        """,
        unsafe_allow_html=True,
    )


# ==========================
# Page Routing
# ==========================

if page == "🚀 Scanner":
    # =====================================
    # SCANNER PAGE
    # =====================================

    st.markdown(
        """
<div class="card">

<div class="title">
🛡 WebShield Scanner
</div>

<div class="subtitle">
Enterprise Website Vulnerability Assessment Platform
</div>

<br>

✔ OWASP Security Testing  
<br>
✔ SSL Analysis  
<br>
✔ DNS Intelligence  
<br>
✔ Vulnerability Risk Scoring

</div>

""",
        unsafe_allow_html=True,
    )
    st.subheader("Python Based Website Vulnerability Scanner")

    # URL input
    st.markdown(
        """
<div class="card">

<h3>
🌐 Target Website
</h3>

</div>
""",
        unsafe_allow_html=True,
    )

    url = st.text_input("", placeholder="https://example.com")

    scan = st.button("🚀 Start Security Scan", use_container_width=True)

    # Start scan button (always visible)
    if st.button("🚀 Start Scan", key="start_scan"):

        # Validate input
        if not url or not url.strip():
            st.warning("Please enter a website URL")
            st.stop()
        progress = st.progress(0)
        # Clean and normalize URL
        url = url.strip()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Fix malformed schemes like https:example.com
        if url.startswith("https:") and not url.startswith("https://"):
            url = url.replace("https:", "https://", 1)

        if url.startswith("http:") and not url.startswith("http://"):
            url = url.replace("http:", "http://", 1)

        st.success(f"Scanning: {url}")

        # ==========================
        # PROGRESS BAR
        # ==========================

        # -------------------------------------
        # Run your scanner functions below
        # Example:
        # info = get_website_info(url)
        # progress.progress(10)
        #
        # tech = detect_technology(url)
        # progress.progress(20)
        #
        # headers = check_headers(url)
        # progress.progress(30)
        # -------------------------------------

        # ==========================
        # WEBSITE INFORMATION
        # ==========================

        progress.progress(10)

        st.header("🌐 Website Information")

        info = safe_scan(get_website_info, url)

        st.write(info)

        # ==========================
        # TECHNOLOGY
        # ==========================

        progress.progress(20)

        st.header("🛠 Technology Detection")

        tech = safe_scan(detect_technology, url)

        st.write(tech)

        # ==========================
        # HEADERS
        # ==========================

        progress.progress(35)

        st.header("🛡 Security Headers")

        headers = safe_scan(check_headers, url)

        if not isinstance(headers, dict):

            headers = {}

        st.write(headers)

        # ==========================
        # SSL
        # ==========================

        progress.progress(50)

        st.header("🔒 SSL Scan")

        ssl_info = safe_scan(scan_ssl, url)

        st.write(ssl_info)

        # ==========================
        # COOKIES
        # ==========================

        progress.progress(60)

        st.header("🍪 Cookie Security")

        cookies = safe_scan(scan_cookies, url)

        st.write(cookies)

        # ==========================
        # PORT SCANNER
        # ==========================

        progress.progress(70)

        st.header("🔍 Port Scanner")

        port_results = safe_scan(scan_ports, url)

        st.write(port_results)

        # ==========================
        # DNS SCANNER
        # ==========================

        st.header("🌐 DNS Security")

        dns_results = safe_scan(scan_dns, url)

        st.write(dns_results)

        # ==========================
        # SUBDOMAIN
        # ==========================

        st.header("🕵️ Subdomain Scanner")

        subdomains = safe_scan(scan_subdomains, url)

        st.write(subdomains)

        # ==========================
        # HTTP METHODS
        # ==========================

        progress.progress(75)

        methods = safe_scan(scan_http_methods, url)

        st.header("🌐 HTTP Methods")

        st.write(methods)

        # ==========================
        # OWASP Vulnerability Scan
        # ==========================

        progress.progress(85)

        st.header("🔥 OWASP Vulnerability Scan")

        raw_vulnerabilities = []

        scanners = [
            scan_xss,
            scan_sql,
            scan_cors,
            scan_misconfiguration,
            scan_directory_listing,
            scan_open_redirect,
            scan_information_disclosure,
            scan_ssrf,
        ]

        for scanner in scanners:

            result = safe_scan(scanner, url)

            if isinstance(result, list):

                for item in result:

                    if item:
                        raw_vulnerabilities.append(item)

            elif result:

                raw_vulnerabilities.append(result)

        # ==========================
        # Remove Duplicate Raw Vulnerabilities
        # ==========================

        clean_raw = []

        seen_names = set()

        for vuln in raw_vulnerabilities:

            if isinstance(vuln, dict):

                name = (
                    vuln.get("name")
                    or vuln.get("Name")
                    or vuln.get("Vulnerability")
                    or "Unknown"
                )

                if name not in seen_names:

                    seen_names.add(name)
                    clean_raw.append(vuln)

        raw_vulnerabilities = clean_raw

        # ==========================
        # Vulnerability Analysis
        # ==========================

        vulnerabilities = []

        for vuln in raw_vulnerabilities:

            if not vuln:
                continue

            try:

                vuln_name = (
                    vuln.get("name")
                    or vuln.get("Name")
                    or vuln.get("Vulnerability")
                    or "Unknown Vulnerability"
                )

                status = vuln.get("status") or vuln.get("Status") or "Unknown"

                if status in ["Not Detected", "Not Vulnerable"]:
                    continue

                cvss_result = calculate_cvss(vuln_name)

                if isinstance(cvss_result, dict):

                    severity = cvss_result.get("severity", "Unknown")

                else:

                    severity = "Unknown"

                owasp_info = get_owasp_details(vuln_name)

                cve_results = search_cve(vuln_name)

                recommendation = generate_recommendation(vuln_name)

                vulnerability_details = {
                    "name": vuln_name,
                    "status": status,
                    "severity": severity,
                    "cvss": cvss_result,
                    "analysis": analyze_vulnerability(vuln_name),
                    "cve": cve_results,
                    "owasp": owasp_info.get("category", "Unknown"),
                    "cwe": owasp_info.get("cwe", "Unknown"),
                    "owasp_description": owasp_info.get("description", ""),
                    "recommendation": recommendation,
                }

                vulnerabilities.append(vulnerability_details)

            except Exception as e:

                st.warning(f"Vulnerability Error: {e}")

        # ==========================
        # Smart Duplicate Removal
        # ==========================

        unique_vulnerabilities = []

        seen = set()

        for vuln in vulnerabilities:

            name = vuln.get("name", "Unknown")

            clean_name = (
                name.lower().replace("server ", "").replace("security ", "").strip()
            )

            if clean_name not in seen:

                seen.add(clean_name)

                unique_vulnerabilities.append(vuln)

        vulnerabilities = unique_vulnerabilities

        # ==========================
        # Vulnerability Display
        # ==========================

        st.subheader("🚨 Vulnerabilities Detected")

        if not vulnerabilities:

            st.success("✅ No vulnerabilities detected")

        else:

            for vuln in vulnerabilities:

                st.markdown("---")

                st.write("### 🚨", vuln["name"])

                st.write("Severity:", vuln["severity"])

                st.write("CVSS:", vuln["cvss"])

                st.write("OWASP:", vuln["owasp"])

                st.write("Recommendation:", vuln["recommendation"])

        # ==========================
        # CVE Report
        # ==========================

        st.subheader("🛡 CVE Intelligence Report")

        for vuln in vulnerabilities:

            st.write(f"### {vuln['name']}")

            if vuln["cve"]:

                st.write(vuln["cve"])

            else:

                st.info("No CVE information found")

        # ==========================
        # OWASP Mapping
        # ==========================

        st.subheader("🔥 OWASP Top 10 Mapping")

        for vuln in vulnerabilities:

            st.markdown("---")

            st.write("Issue:", vuln["name"])

            st.write("Category:", vuln["owasp"])

        # ==========================
        # Severity
        # ==========================

        severity_report = calculate_severity(vulnerabilities)

        st.subheader("⚠️ Vulnerability Severity")

        st.json(severity_report)

        # ==========================
        # Security Score
        # ==========================

        progress.progress(90)

        score = calculate_score(headers, ssl_info, cookies, methods)

        if score >= 90:

            severity = "Low Risk"

        elif score >= 70:

            severity = "Medium Risk"

        else:

            severity = "High Risk"

        # ==========================
        # Professional Scan Metrics
        # ==========================

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            metric_card("Security Score", f"{score}/100", "🛡")

        with col2:
            metric_card("Issues", len(raw_vulnerabilities), "⚠️")

        with col3:
            metric_card("Risk Level", severity, "🔥")

        with col4:
            metric_card("Status", "Completed", "✅")

        # ==========================
        # Save Database
        # ==========================

        saved = save_scan(url, score, severity, vulnerabilities, severity_report)

        if saved:

            st.success("💾 Database Saved Successfully")

        else:

            st.error("❌ Database Save Failed")

        # ==========================
        # Scan Comparison
        # ==========================

        comparison = compare_scan(url, score, vulnerabilities)

        st.subheader("📈 Scan Comparison")

        if comparison["status"] == "First Scan":

            st.info(comparison["message"])

        else:

            st.metric("Previous Score", comparison["old_score"])

            st.metric("Current Score", comparison["new_score"])

        # ==========================
        # Complete
        # ==========================

        progress.progress(100)

        st.success("✅ Scan Completed Successfully")

        # ==========================
        # PDF Report
        # ==========================

        report_data = {
            "URL": url,
            "Security Score": {"Score": score, "Severity": severity},
            "Vulnerabilities": vulnerabilities,
        }

        try:

            pdf = generate_professional_report("WebShield_Report.pdf", report_data)

            st.download_button(
                label="📄 Download Professional PDF Report",
                data=pdf,
                file_name="WebShield_Report.pdf",
                mime="application/pdf",
                key=f"professional_pdf_download_{uuid.uuid4()}",
            )

        except Exception as e:

            st.error(f"PDF Error: {e}")

    # =====================================
# DASHBOARD PAGE
# =====================================

if page == "Dashboard":

    st.title("📊 Security Dashboard")

    show_dashboard()
    # =====================================
# SCAN HISTORY PAGE
# =====================================

if page == "Scan History":

    st.title("📜 Scan History")

    # ==========================
    # GET HISTORY DATA
    # ==========================

    history = get_history()

    # ==========================
    # DISPLAY HISTORY
    # ==========================

    st.subheader("🗂 Previous Scans")

    import json

    if not history:

        st.info("No previous scans found.")

    else:

        for scan in history:

            with st.container():

                st.markdown("---")

                st.write("🌐 Website")

                st.code(scan[1])

                st.write("📊 Security Score")

                st.success(f"{scan[2]}/100")

                st.write("⚠️ Risk Level")

                st.warning(scan[3])

                st.write("📅 Scan Date")

                st.write(scan[6])

                if scan[4]:

                    with st.expander("🚨 View Vulnerabilities"):

                        try:

                            st.json(json.loads(scan[4]))

                        except:

                            st.write(scan[4])

                if st.button(f"🗑 Delete Scan {scan[0]}", key=f"delete_scan_{scan[0]}"):

                    delete_scan(scan[0])

                    st.success("Scan deleted successfully")

                    st.rerun()
# =====================================
# ADMIN PANEL
# =====================================

if page == "Admin Panel":

    if st.session_state.role == "admin":

        st.title("👨‍💼 Admin Panel")

        show_admin_panel()

    else:

        st.error("❌ Access Denied")
# ==========================
# Dashboard Page
# ==========================

elif page == "📊 Dashboard":

    show_dashboard()


# ==========================
# History Page
# ==========================

elif page == "📜 History":

    st.title("📜 Scan History")

    history = get_history()

    if history:

        for scan in history:

            st.write(
                {"Website": scan[1], "Score": scan[2], "Risk": scan[3], "Date": scan[6]}
            )

    else:

        st.info("No scan history available.")


# ==========================
# Admin Page
# ==========================

elif page == "⚙ Admin":

    show_admin_panel()
