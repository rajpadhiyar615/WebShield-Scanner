import requests

def scan_cookies(url):

    try:

        response = requests.get(url, timeout=10)

        set_cookie_headers = response.raw.headers.get_all("Set-Cookie") or []

        cookies = []

        for header in set_cookie_headers:

            cookies.append({

                "Raw Header": header,
                "Secure": "Secure" in header,
                "HttpOnly": "HttpOnly" in header,

                "SameSite":
                    "Strict" if "SameSite=Strict" in header
                    else "Lax" if "SameSite=Lax" in header
                    else "None" if "SameSite=None" in header
                    else "Not Set"

            })

        return cookies

    except Exception as e:

        return {"Error": str(e)}