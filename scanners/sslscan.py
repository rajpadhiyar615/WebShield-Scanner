import ssl
import socket
from datetime import datetime


def scan_ssl(url):

    result = {}

    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    try:

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                certificate = ssock.getpeercert()

                # HTTPS Status

                result["HTTPS"] = "Enabled"

                # TLS Version

                result["TLS Version"] = ssock.version()

                # Cipher

                cipher = ssock.cipher()

                result["Cipher"] = cipher[0]

                # Certificate Issuer

                issuer = dict(x[0] for x in certificate["issuer"])

                result["Issuer"] = issuer.get("organizationName", "Unknown")

                # Expiry

                expiry = datetime.strptime(
                    certificate["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )

                days_left = (expiry - datetime.utcnow()).days

                result["Expiry Date"] = expiry.strftime("%d-%m-%Y")

                result["Days Remaining"] = days_left

                if days_left < 30:

                    result["Certificate Status"] = "Expiring Soon ⚠️"

                else:

                    result["Certificate Status"] = "Valid ✅"

    except Exception as e:

        result["HTTPS"] = "Disabled"

        result["Error"] = str(e)

    return result
