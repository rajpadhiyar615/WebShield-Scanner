import socket


def scan_ports(url):

    results = []

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP Proxy",
    }

    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    for port, service in common_ports.items():

        try:

            sock = socket.socket()

            sock.settimeout(1)

            result = sock.connect_ex((hostname, port))

            if result == 0:

                status = "Open"

            else:

                status = "Closed"

            results.append({"Port": port, "Service": service, "Status": status})

            sock.close()

        except Exception:

            pass

    return results
