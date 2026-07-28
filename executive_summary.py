def generate_summary(score, severity, vulnerabilities):

    total = len(vulnerabilities)

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    summary = {
        "grade": grade,
        "score": score,
        "risk": severity,
        "vulnerabilities": total,
    }

    return summary
