import requests
from urllib.parse import urlparse


def normalize_url(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def scan_xss(url):

    url = normalize_url(url)

    payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ]

    try:

        for payload in payloads:

            response = requests.get(
                url,
                params={"q": payload},
                timeout=10,
                headers={"User-Agent": "WebShield-Security-Scanner"},
            )

            if payload in response.text:

                return {
                    "name": "Cross Site Scripting (XSS)",
                    "status": "Vulnerable",
                    "severity": "High",
                    "description": "Reflected XSS vulnerability detected. "
                    "User supplied input is reflected without proper sanitization.",
                    "payload": payload,
                }

        return {
            "name": "Cross Site Scripting (XSS)",
            "status": "Not Vulnerable",
            "severity": "Low",
            "description": "No reflected XSS payload detected.",
        }

    except requests.exceptions.Timeout:

        return {
            "name": "Cross Site Scripting (XSS)",
            "status": "Error",
            "severity": "Unknown",
            "description": "Website request timed out.",
        }

    except requests.exceptions.RequestException as e:

        return {
            "name": "Cross Site Scripting (XSS)",
            "status": "Error",
            "severity": "Unknown",
            "description": str(e),
        }
