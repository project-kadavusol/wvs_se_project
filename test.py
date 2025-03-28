import socket
import subprocess
import platform
from urllib.parse import urlparse

def ping(target):
    parsed_url = urlparse(target)
    domain = parsed_url.hostname if parsed_url.hostname else target
    if ':' in domain:
        domain=domain.split(":")[0]
        
    if domain.replace('.', '').isdigit():
        ip = domain
    else:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return f"Invalid domain or IP: {domain}"

    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "2", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return f"{ip} is reachable"
        else:
            return f"Failed to reach {ip}"
    except Exception as e:
        return f"Error: {e}"
