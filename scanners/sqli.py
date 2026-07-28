import requests


def scan_sql(url):

    payload="' OR '1'='1"


    try:

        response=requests.get(

            url,

            params={
                "id":payload
            },

            timeout=10

        )


        errors=[
            "mysql",
            "syntax error",
            "database error",
            "sql"
        ]


        for error in errors:

            if error in response.text.lower():

                return {

                "Vulnerability":
                "SQL Injection",

                "Status":
                "Potentially Vulnerable",

                "Severity":
                "Critical"

                }


        return {

        "Vulnerability":
        "SQL Injection",

        "Status":
        "Not Detected",

        "Severity":
        "Low"

        }



    except Exception as e:

        return {
            "Error":str(e)
        }