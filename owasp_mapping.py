# =====================================
# OWASP Top 10 Mapping
# =====================================


def get_owasp_category(vulnerability):

    vuln = str(vulnerability).lower()

    if "sql" in vuln or "injection" in vuln:

        return {
            "category": "A03:2021 Injection",
            "description": "SQL Injection or command injection vulnerability",
        }

    elif "xss" in vuln or "cross" in vuln:

        return {
            "category": "A03:2021 Injection",
            "description": "Cross Site Scripting vulnerability",
        }

    elif "cors" in vuln:

        return {
            "category": "A05:2021 Security Misconfiguration",
            "description": "Improper CORS configuration",
        }

    elif "cookie" in vuln:

        return {
            "category": "A07:2021 Identification and Authentication Failures",
            "description": "Weak cookie security configuration",
        }

    elif "ssl" in vuln or "tls" in vuln:

        return {
            "category": "A02:2021 Cryptographic Failures",
            "description": "Weak encryption configuration",
        }

    elif "redirect" in vuln:

        return {
            "category": "A10:2021 Server-Side Request Forgery",
            "description": "Unsafe redirect behaviour",
        }

    else:

        return {"category": "Unknown", "description": "Manual security review required"}
