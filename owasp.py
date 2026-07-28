OWASP_DETAILS = {
    "Cross Site Scripting (XSS)": {
        "category": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "severity": "High",
        "description": "Application reflects or executes untrusted user input without proper sanitization.",
    },
    "SQL Injection": {
        "category": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "severity": "Critical",
        "description": "Improper validation allows attackers to manipulate SQL queries.",
    },
    "CORS Misconfiguration": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-942",
        "severity": "Medium",
        "description": "Improper Cross-Origin Resource Sharing configuration may expose sensitive resources.",
    },
    "Security Misconfiguration": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-16",
        "severity": "High",
        "description": "Insecure server or application configuration increases security risk.",
    },
    "Directory Listing": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-548",
        "severity": "Medium",
        "description": "Directory indexing exposes files and folders to unauthorized users.",
    },
    "Directory Listing Enabled": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-548",
        "severity": "Medium",
        "description": "Directory indexing exposes files and folders to unauthorized users.",
    },
    "Open Redirect": {
        "category": "A01:2021 - Broken Access Control",
        "cwe": "CWE-601",
        "severity": "Medium",
        "description": "Users can be redirected to malicious websites through untrusted URLs.",
    },
    "Information Disclosure": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "severity": "Low",
        "description": "Sensitive information such as software versions or error details is exposed.",
    },
    "Server Information Disclosure": {
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "severity": "Low",
        "description": "Server banner or version information is publicly exposed.",
    },
    "SSRF": {
        "category": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "High",
        "description": "The server can be tricked into making requests to unintended internal or external resources.",
    },
    "Server Side Request Forgery": {
        "category": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "High",
        "description": "The server can be forced to access internal or restricted resources.",
    },
}


def get_owasp_details(name):

    name = str(name).strip()

    # Direct match
    if name in OWASP_DETAILS:
        return OWASP_DETAILS[name]

    # Partial match for scanner output variations
    name_lower = name.lower()

    if "xss" in name_lower or "cross site" in name_lower:
        return OWASP_DETAILS["Cross Site Scripting (XSS)"]

    if "sql" in name_lower:
        return OWASP_DETAILS["SQL Injection"]

    if "cors" in name_lower:
        return OWASP_DETAILS["CORS Misconfiguration"]

    if "directory" in name_lower:
        return OWASP_DETAILS["Directory Listing"]

    if "redirect" in name_lower:
        return OWASP_DETAILS["Open Redirect"]

    if "information" in name_lower:
        return OWASP_DETAILS["Information Disclosure"]

    if "server information" in name_lower:
        return OWASP_DETAILS["Server Information Disclosure"]

    if "ssrf" in name_lower or "request forgery" in name_lower:
        return OWASP_DETAILS["SSRF"]

    return {
        "category": "Unknown",
        "cwe": "Unknown",
        "severity": "Unknown",
        "description": "No OWASP mapping available.",
    }
