import requests


def scan_subdomains(url):

    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    common_subdomains = [
        "www",
        "mail",
        "api",
        "dev",
        "test",
        "admin",
        "portal",
        "blog",
        "shop",
        "staging",
    ]

    found = []

    for sub in common_subdomains:

        subdomain = f"https://{sub}.{hostname}"

        try:

            response = requests.get(subdomain, timeout=3)

            if response.status_code < 500:

                found.append(
                    {
                        "Subdomain": subdomain,
                        "Status": response.status_code,
                        "Found": True,
                    }
                )

        except Exception:

            pass

    return found
