import socket
from urllib.parse import urlparse

stored_domains = set()
stored_ips = set()
with open("newlist", "r") as file:
    for line in file:
        line = line.strip().lower()
        if "." in line and ":" not in line:
            stored_domains.add(line)
        elif line.replace(".", "").isdigit():
            stored_ips.add(line)

def extract_domain(input_url):
    parsed_url = urlparse(input_url)
    domain = parsed_url.netloc or parsed_url.path
    domain = domain.lower().lstrip("www.")
    return domain

def check_url(input_url):
    domain = extract_domain(input_url)

    if not domain:
        return False

    if domain in stored_domains or "www." + domain in stored_domains:
        return True

    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip in stored_ips:
            return True
    except socket.gaierror:
        print(f"Could not resolve {domain}")

    return False

