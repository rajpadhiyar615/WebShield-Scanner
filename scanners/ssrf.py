import requests



def scan_ssrf(url):


    payload="?url=http://127.0.0.1"


    try:


        response=requests.get(

            url+payload,

            timeout=5

        )


        if "localhost" in response.text:


            return {

            "Vulnerability":
            "SSRF",

            "Status":
            "Potentially Vulnerable"

            }



        return {

        "Vulnerability":
        "SSRF",

        "Status":
        "Secure"

        }



    except Exception as e:


        return {

        "Vulnerability":
        "SSRF",

        "Status":
        str(e)

        }