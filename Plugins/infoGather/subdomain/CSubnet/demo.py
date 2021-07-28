
def filter_internal_ip(ip_subnet):
    ip_subnet_list = ip_subnet.split('.')
    if ip_subnet_list[0] == '10' or '127':
        return None
    elif ip_subnet_list[0] == '172' and 15 < int(ip_subnet_list[1]) < 32:
        return None
    elif ip_subnet_list[0] == '192' and ip_subnet_list[1] == '168':
        return None
    else:
        return ip_subnet


for _ in ['10.0.0', '1.1.1', '192.168', '172.16.1', '172.14.2']:
    ip_subnet = filter_internal_ip(_)
    print(ip_subnet)