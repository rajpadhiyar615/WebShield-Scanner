from database import get_previous_scan
import json


def compare_scan(url, current_score, current_vulnerabilities):

    previous = get_previous_scan(url)

    if not previous:

        return {
            "status": "First Scan",
            "message": "This is the first scan for this website.",
        }

    old_score = previous[2]

    old_vulnerabilities = json.loads(previous[4])

    difference = current_score - old_score

    return {
        "status": "Compared",
        "old_score": old_score,
        "new_score": current_score,
        "difference": difference,
        "new_vulnerabilities": [],
    }
