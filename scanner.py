def calculate_score(headers, ssl_info, cookies, methods):

    score = 100

    # ==========================
    # Security Headers Check
    # ==========================

    if isinstance(headers, dict):

        for value in headers.values():

            if value == "Missing":
                score -= 5

    # ==========================
    # SSL Certificate Check
    # ==========================

    if isinstance(ssl_info, dict):

        if ssl_info.get("HTTPS") != "Enabled":
            score -= 20

    # ==========================
    # Cookie Security Check
    # ==========================

    if isinstance(cookies, list):

        for cookie in cookies:

            if isinstance(cookie, dict):

                if not cookie.get("Secure", False):
                    score -= 5

                if not cookie.get("HttpOnly", False):
                    score -= 5

    # ==========================
    # HTTP Methods Check
    # ==========================

    dangerous_methods = {"PUT", "DELETE", "TRACE"}

    if isinstance(methods, list):

        for method in methods:

            if method in dangerous_methods:
                score -= 10

    # ==========================
    # Score Validation
    # ==========================

    score = max(score, 0)
    score = min(score, 100)

    return score
