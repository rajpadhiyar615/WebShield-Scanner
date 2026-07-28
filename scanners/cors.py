import requests


def scan_cors(url):

    try:

        response=requests.get(
            url,
            headers={
                "Origin":
                "https://evil.com"
            }
        )


        cors=response.headers.get(
            "Access-Control-Allow-Origin"
        )


        if cors=="*":

            return {

            "Vulnerability":
            "CORS Misconfiguration",

            "Status":
            "Detected",

            "Severity":
            "Medium"

            }


        return {

        "Vulnerability":
        "CORS Misconfiguration",

        "Status":
        "Secure",

        "Severity":
        "Low"

        }



    except Exception as e:

        return {
            "Error":str(e)
        }