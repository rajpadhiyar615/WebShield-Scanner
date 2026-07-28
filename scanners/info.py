import socket
import whois
import dns.resolver
from urllib.parse import urlparse

def get_website_info(url):
    try:
        # Extract domain
        domain = urlparse(url).netloc
        if domain == "":
            domain = url

        # IP Address
        ip = socket.gethostbyname(domain)

        # Hostname
        hostname = socket.getfqdn(domain)

        # WHOIS
        try:
            w = whois.whois(domain)
        except:
            w = None

        # DNS Records
        dns_records = []

        try:
            answers = dns.resolver.resolve(domain, "A")
            for rdata in answers:
                dns_records.append(rdata.to_text())
        except:
            dns_records.append("No DNS Records Found")

        return {
            "Domain": domain,
            "IP Address": ip,
            "Hostname": hostname,
            "Registrar": getattr(w, "registrar", "Unknown") if w else "Unknown",
            "Creation Date": str(getattr(w, "creation_date", "Unknown")) if w else "Unknown",
            "Expiration Date": str(getattr(w, "expiration_date", "Unknown")) if w else "Unknown",
            "Name Servers": str(getattr(w, "name_servers", "Unknown")) if w else "Unknown",
            "DNS Records": dns_records
        }

    except Exception as e:
        return {"Error": str(e)}