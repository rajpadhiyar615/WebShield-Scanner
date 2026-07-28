import requests



def scan_open_redirect(url):


    test_url = url + "?redirect=https://google.com"


    try:


        response=requests.get(

            test_url,

            allow_redirects=False,

            timeout=5

        )



        if response.status_code in [301,302,307]:


            return {

            "Vulnerability":
            "Open Redirect",

            "Status":
            "Potentially Vulnerable"

            }


        return {

        "Vulnerability":
        "Open Redirect",

        "Status":
        "Secure"

        }


    except Exception as e:


        return {

        "Vulnerability":
        "Open Redirect",

        "Status":
        str(e)

        }