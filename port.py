import socket
import concurrent.futures
import time
from urllib.parse import urlparse
from tabulate import tabulate

def port_scan(target):
    parsed_url = urlparse(target)
    domain = parsed_url.hostname if parsed_url.hostname else target
    if domain.replace('.', '').isdigit():
        ip = domain
    else:
        ip = socket.gethostbyname(domain)

    start_port = 0
    end_port = 65535
    start_time = time.time()

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "unknown"
                    return [port, "open", service]
        except:
            return None

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2000) as executor:
        results = executor.map(scan_port, range(start_port, end_port + 1))

    for result in results:
        if result:
            open_ports.append(result)

    if open_ports:
        table_headers = ["PORT", "STATE", "SERVICE"]
        output = tabulate(open_ports, headers=table_headers, tablefmt="grid")
    else:
        output = "No open ports found."

    end_time = time.time()
    output += f"\n\nScan completed in {end_time - start_time:.2f} seconds."

    return output

"print(port_scan('192.168.200.251'))"