import requests

def scan_sitemap(url):
    try:
        if url.endswith("/"):
            sitemap_url = url + "sitemap.xml"
        else:
            sitemap_url = url + "/sitemap.xml"

        response = requests.get(sitemap_url, timeout=10)

        if response.status_code == 200:
            return {
                "Found": True,
                "URL": sitemap_url
            }

        return {
            "Found": False,
            "URL": sitemap_url
        }

    except Exception as e:
        return {"Error": str(e)}