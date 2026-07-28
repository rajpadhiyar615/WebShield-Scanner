import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(keyword):

    try:

        params = {"keywordSearch": keyword, "resultsPerPage": 3}

        response = requests.get(NVD_API, params=params, timeout=10)

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]

            vulnerabilities.append(
                {
                    "id": cve["id"],
                    "description": cve["descriptions"][0]["value"],
                }
            )

        return vulnerabilities

    except Exception as e:

        return {"error": str(e)}
