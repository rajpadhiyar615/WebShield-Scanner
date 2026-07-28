import pandas as pd
import json


def export_csv(data):

    df = pd.DataFrame(

        data,

        columns=[

            "ID",
            "URL",
            "Score",
            "Severity",
            "Vulnerabilities",
            "Date"

        ]

    )


    return df.to_csv(
        index=False
    )



def export_json(data):


    result=[]


    for scan in data:


        result.append({

            "id":scan[0],

            "website":scan[1],

            "score":scan[2],

            "severity":scan[3],

            "vulnerabilities":

                json.loads(scan[4]),

            "date":scan[5]

        })


    return json.dumps(

        result,

        indent=4

    )