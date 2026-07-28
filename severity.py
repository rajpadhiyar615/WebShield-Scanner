def calculate_severity(vulnerabilities):

    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for vuln in vulnerabilities:

        if isinstance(vuln, dict):

            severity = vuln.get("severity", "Low")

            severity = severity.capitalize()

            if severity in severity_count:
                severity_count[severity] += 1

    return severity_count
