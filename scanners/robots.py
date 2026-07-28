import requests

def scan_robots(url):
    try:
        if url.endswith("/"):
            robots_url = url + "robots.txt"
        else:
            robots_url = url + "/robots.txt"

        response = requests.get(robots_url, timeout=10)

        if response.status_code == 200:
            return {
                "Found": True,
                "URL": robots_url,
                "Content": response.text
            }

        return {
            "Found": False,
            "URL": robots_url
        }

    except Exception as e:
        return {"Error": str(e)}