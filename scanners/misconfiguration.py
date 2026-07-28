import requests


def scan_misconfiguration(url):

    findings=[]


    try:

        response=requests.get(
            url,
            timeout=5
        )


        headers=response.headers



        if "Server" in headers:

            findings.append({

                "Vulnerability":
                "Server Information Disclosure",

                "Status":
                "Potentially Vulnerable"

            })


        else:

            findings.append({

                "Vulnerability":
                "Server Information Disclosure",

                "Status":
                "Secure"

            })


        if response.url.endswith("/"):

            findings.append({

                "Vulnerability":
                "Directory Listing",

                "Status":
                "Check Required"

            })



    except Exception as e:


        findings.append({

            "Vulnerability":
            "Security Misconfiguration",

            "Status":
            str(e)

        })


    return findings