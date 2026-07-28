import requests



def scan_directory_listing(url):


    paths=[

        "/uploads/",
        "/backup/",
        "/admin/",
        "/files/"

    ]


    results=[]


    for path in paths:


        try:


            response=requests.get(

                url+path,

                timeout=3

            )


            if response.status_code==200:


                if "Index of" in response.text:


                    results.append({

                    "Vulnerability":
                    "Directory Listing Enabled",

                    "Status":
                    "Vulnerable"

                    })


        except:

            pass



    if not results:


        results.append({

        "Vulnerability":
        "Directory Listing",

        "Status":
        "Secure"

        })


    return results