import requests

def scan_http_methods(url):
    try:
        response = requests.options(url, timeout=10)

        allow = response.headers.get("Allow", "")

        if allow:
            methods = [method.strip() for method in allow.split(",")]
        else:
            methods = ["GET", "POST"]

        return methods

    except Exception as e:
        return {"Error": str(e)}