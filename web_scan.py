import test,port,socket
def all_scan(target):
    target=target.split(":")[0]
    if target.replace(".", "").isdigit():
       ip=target
    else:
         domain = target.split("//")[-1].split("/")[0]
         ip=(socket.gethostbyname(domain))
    print(test.ping(ip))
    port.port_scan(ip)