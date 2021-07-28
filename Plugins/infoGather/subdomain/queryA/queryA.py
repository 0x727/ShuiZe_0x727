# 查询子域名的A记录
import re
from queue import Queue
from threading import Thread
import dns

def query_A(t_id, subtract_subdomains_queue, Subdomains_ips):     # 查询A记录的IP
    while not subtract_subdomains_queue.empty():
        subdomain = subtract_subdomains_queue.get()
        # print('{}, '.format(subdomain), end='')
        try:
            dns_A_ips = [j for i in dns.resolver.query(subdomain, 'A').response.answer for j in i.items]
            ips = []
            for each_ip in dns_A_ips:
                each_ip = str(each_ip)
                if re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$').match(each_ip):    # 正则匹配是否是IP
                    ips.append(str(each_ip))
            Subdomains_ips[subdomain] = ips
        except Exception as e:
            Subdomains_ips[subdomain] = []

def run_queryA(Subdomains_ips, subdomains):
    query_A_threads = []  # 存放线程
    subtract_subdomains_queue = Queue(-1)

    for subdomain in subdomains:
        subtract_subdomains_queue.put(subdomain)

    # print('query A : ', end='')


    for t_id in range(50):       # 对新增的子域名进行A记录查询获取IP
        t = Thread(target=query_A, args=(t_id, subtract_subdomains_queue, Subdomains_ips))
        query_A_threads.append(t)
        t.start()
    for t in query_A_threads:
        t.join()

    # print()
    return Subdomains_ips