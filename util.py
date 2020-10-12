from ipaddress import ip_network


def parse_cidr(cidr):
    ips = []
    for ip in ip_network(cidr, strict=False).hosts():
        ips.append(str(ip))
    return ips
