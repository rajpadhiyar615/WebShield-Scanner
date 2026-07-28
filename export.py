import pandas as pd
from database import get_history


def export_csv():

    history = get_history()

    if not history:
        return None

    data = []

    for scan in history:

        data.append(
            {
                "Website": scan[1],
                "Score": scan[2],
                "Risk": scan[3],
                "Vulnerabilities": scan[4],
                "Scan Date": scan[5],
            }
        )

    df = pd.DataFrame(data)

    filename = "ScanHistory.csv"

    df.to_csv(filename, index=False)

    return filename


def export_excel():

    history = get_history()

    if not history:
        return None

    data = []

    for scan in history:

        data.append(
            {
                "Website": scan[1],
                "Score": scan[2],
                "Risk": scan[3],
                "Vulnerabilities": scan[4],
                "Scan Date": scan[5],
            }
        )

    df = pd.DataFrame(data)

    filename = "ScanHistory.xlsx"

    df.to_excel(filename, index=False)

    return filename
