import requests

def check_headers(url):
    try:
        response = requests.get(url, timeout=10)

        important_headers = [
            "Server",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection"
        ]

        results = {}

        for header in important_headers:
            results[header] = response.headers.get(header, "Missing")

        return results

    except Exception as e:
        return {"Error": str(e)}