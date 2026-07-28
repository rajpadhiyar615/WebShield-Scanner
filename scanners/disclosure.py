import requests



def scan_information_disclosure(url):


    sensitive=[

        ".git/config",

        ".env",

        "config.php",

        "backup.zip"

    ]


    results=[]



    for item in sensitive:


        try:


            response=requests.get(

                url+"/"+item,

                timeout=3

            )



            if response.status_code==200:


                results.append({

                "Vulnerability":
                "Sensitive File Exposure",

                "Status":
                "Vulnerable"

                })


        except:

            pass



    if not results:


        results.append({

        "Vulnerability":
        "Information Disclosure",

        "Status":
        "Secure"

        })



    return results