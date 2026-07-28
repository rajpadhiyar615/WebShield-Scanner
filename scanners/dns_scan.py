import dns.resolver


def scan_dns(url):

    results = {}

    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    records = [
        "A",
        "MX",
        "TXT",
    ]

    for record in records:

        try:

            answers = dns.resolver.resolve(hostname, record)

            results[record] = [str(answer) for answer in answers]

        except Exception:

            results[record] = "Not Found"

    # SPF Check

    spf_found = False

    try:

        txt_records = dns.resolver.resolve(hostname, "TXT")

        for txt in txt_records:

            value = str(txt)

            if "spf" in value.lower():

                spf_found = True

    except Exception:

        pass

    results["SPF"] = "Configured" if spf_found else "Missing"

    # DMARC Check

    try:

        dmarc = dns.resolver.resolve("_dmarc." + hostname, "TXT")

        results["DMARC"] = [str(x) for x in dmarc]

    except Exception:

        results["DMARC"] = "Missing"

    return results
