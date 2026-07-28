def calculate_cvss(vulnerability):

    vulnerability = str(vulnerability).lower()

    # SQL Injection
    if "sql" in vulnerability:

        return {
            "score": 9.8,
            "severity": "Critical",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "High",
        }

    # Cross Site Scripting
    elif "xss" in vulnerability or "cross site scripting" in vulnerability:

        return {
            "score": 6.1,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "Medium",
        }

    # CORS Misconfiguration
    elif "cors" in vulnerability:

        return {
            "score": 5.3,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Medium",
            "privileges": "None",
            "impact": "Low",
        }

    # Directory Listing
    elif "directory" in vulnerability:

        return {
            "score": 4.3,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "Low",
        }

    # Open Redirect
    elif "redirect" in vulnerability:

        return {
            "score": 6.1,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "Medium",
        }

    # Information Disclosure
    elif (
        "information disclosure" in vulnerability
        or "server information disclosure" in vulnerability
    ):

        return {
            "score": 5.3,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "Low",
        }

    # SSRF
    elif "ssrf" in vulnerability:

        return {
            "score": 8.6,
            "severity": "High",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "Low",
            "impact": "High",
        }

    # Security Misconfiguration
    elif "misconfiguration" in vulnerability:

        return {
            "score": 6.5,
            "severity": "Medium",
            "attack_vector": "Network",
            "complexity": "Low",
            "privileges": "None",
            "impact": "Medium",
        }

    # Default
    else:

        return {
            "score": 3.0,
            "severity": "Low",
            "attack_vector": "Network",
            "complexity": "High",
            "privileges": "None",
            "impact": "Low",
        }
