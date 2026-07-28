# =====================================
# Security Recommendation Engine
# =====================================


def generate_recommendation(vulnerability):

    # Handle dictionary input from scanners
    if isinstance(vulnerability, dict):

        vuln_name = (
            vulnerability.get("Vulnerability")
            or vulnerability.get("name")
            or vulnerability.get("vulnerability")
            or ""
        )

    else:

        vuln_name = str(vulnerability)

    vuln = vuln_name.lower()

    # ==========================
    # SQL Injection
    # ==========================

    if "sql" in vuln or "injection" in vuln:

        return {
            "issue": "SQL Injection",
            "impact": "Attackers can manipulate database queries and access sensitive data.",
            "fix": [
                "Use parameterized queries",
                "Avoid dynamic SQL queries",
                "Validate and sanitize user input",
                "Apply database least privilege",
            ],
        }

    # ==========================
    # XSS
    # ==========================

    elif "xss" in vuln or "cross site scripting" in vuln:

        return {
            "issue": "Cross Site Scripting (XSS)",
            "impact": "Attackers can execute malicious JavaScript in victim browsers.",
            "fix": [
                "Implement output encoding",
                "Sanitize user input",
                "Enable Content Security Policy (CSP)",
                "Use secure frameworks",
            ],
        }

    # ==========================
    # CORS
    # ==========================

    elif "cors" in vuln:

        return {
            "issue": "CORS Misconfiguration",
            "impact": "Unauthorized websites may access sensitive resources.",
            "fix": [
                "Restrict allowed origins",
                "Avoid wildcard (*) origins",
                "Validate HTTP requests",
            ],
        }

    # ==========================
    # SSL/TLS
    # ==========================

    elif "ssl" in vuln or "tls" in vuln:

        return {
            "issue": "Weak SSL/TLS Configuration",
            "impact": "Encrypted communication may be vulnerable.",
            "fix": [
                "Enable TLS 1.2 or TLS 1.3",
                "Disable weak ciphers",
                "Renew expired certificates",
            ],
        }

    # ==========================
    # Directory Listing
    # ==========================

    elif "directory" in vuln:

        return {
            "issue": "Directory Listing Enabled",
            "impact": "Attackers can view sensitive files and folders.",
            "fix": [
                "Disable directory indexing",
                "Restrict folder permissions",
                "Remove sensitive files",
            ],
        }

    # ==========================
    # Information Disclosure
    # ==========================

    elif "disclosure" in vuln or "information" in vuln:

        return {
            "issue": "Information Disclosure",
            "impact": "Sensitive information may be exposed.",
            "fix": [
                "Remove server version details",
                "Hide error messages",
                "Review application logs",
            ],
        }

    # ==========================
    # SSRF
    # ==========================

    elif "ssrf" in vuln:

        return {
            "issue": "Server Side Request Forgery",
            "impact": "Attackers may access internal services.",
            "fix": ["Validate URLs", "Restrict outbound requests", "Use allowlists"],
        }

    # ==========================
    # Default
    # ==========================

    else:

        return {
            "issue": "Security Issue Detected",
            "impact": "Manual security assessment required.",
            "fix": [
                "Review configuration",
                "Apply security best practices",
                "Update vulnerable components",
            ],
        }
