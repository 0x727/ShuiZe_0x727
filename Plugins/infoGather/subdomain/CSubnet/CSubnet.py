import re
from sys import version_info
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import socket
from threading import Thread
from collections import defaultdict
import sqlite3


from queue import Queue

# 获取C段
class CSubnet:
    def __init__(self, domain, allSubdomains, infoGather_db_file):
        self.domain = domain
        self.allSubdomains = allSubdomains
        # self.save_fold_path = save_fold_path
        self.threadsNum = 20
        self.threads = []
        self.temp_allSubdomains = Queue(-1)
        self.C_IPs_sub = set()
        self.CSubnetIPS = []
        self.subdomain_ip = []        # 存放域名和IP
        self.subnet_to_domain = defaultdict(list)       # 每个C段有多少个域名
        self.infoGather_db_file = infoGather_db_file

    def run(self):
        for _ in self.allSubdomains:
            self.temp_allSubdomains.put(_)

        for i in range(1, self.threadsNum + 1):
            t = Thread(target=self.scan)
            self.threads.append(t)
            t.start()
        for t in self.threads:
            t.join()

        for _ in self.subnet_to_domain:
            self.C_IPs_sub.add(_)


        for _ in self.C_IPs_sub:
            for i in range(255):
                ip = '{}.{}'.format(_, i)
                self.CSubnetIPS.append(ip)
        self.CSubnetIPS = list(set(self.CSubnetIPS))


        self.save_to_sqlite_subdomain(self.subdomain_ip)
        self.save_to_sqlite_CSubnetIPS(self.CSubnetIPS)


        return self.CSubnetIPS, self.subdomain_ip

    def scan(self):
        while not self.temp_allSubdomains.empty():
            subdomain = self.temp_allSubdomains.get()
            try:
                ip = socket.getaddrinfo(subdomain.strip(), None)[0][4][0]
                print('\t[+] {} {}'.format(subdomain, ip))
                if len(ip.split('.')) == 4:
                    # with open('{}/domain_ip.txt'.format(self.save_fold_path), 'at') as f:
                    #     f.writelines('[{}]   [{}]\n'.format(subdomain, ip))
                    ip_subnet = ip.rsplit('.', 1)[0]
                    self.subnet_to_domain[ip_subnet].append(subdomain)
                    if self.is_internal_ip(ip_subnet):      # 如果是内网IP，则说明内网IP泄露
                        # with open('{}/internal_ip.txt'.format(self.save_fold_path), 'at') as f:
                        #     f.writelines('[{}]   [{}]\n'.format(subdomain, ip))
                        self.subdomain_ip.append((subdomain, ip, 1))
                    else:
                        self.subdomain_ip.append((subdomain, ip, 0))
            except Exception:
                pass


    def is_internal_ip(self, ip_subnet):
        ip_subnet_list = ip_subnet.split('.')
        if ip_subnet_list[0] == '10' or ip_subnet_list[0] == '127':
            return True
        elif ip_subnet_list[0] == '172' and 15 < int(ip_subnet_list[1]) < 32:
            return True
        elif ip_subnet_list[0] == '192' and ip_subnet_list[1] == '168':
            return True
        else:
            return False

    def save_to_sqlite_subdomain(self, subdomain_ip):
        conn = sqlite3.connect(self.infoGather_db_file)  # 创建数据库
        cu = conn.cursor()  # 能获得连接的游标

        try:
            cu.execute('create table subdomain (SubDomain varchar(50), IP varchar(50), isInternal varchar(5))')  # 创建表
        except Exception as e:
            pass

        for subdomain, ip, isInternal in subdomain_ip:
            sql = "insert into subdomain values('{}', '{}', '{}')".format(subdomain, ip, isInternal)
            print(sql)
            cu.execute(sql)

        conn.commit()
        cu.close()

    def save_to_sqlite_CSubnetIPS(self, CSubnetIPS):
        conn = sqlite3.connect(self.infoGather_db_file)  # 创建数据库
        cu = conn.cursor()  # 能获得连接的游标

        try:
            cu.execute('create table CSubnetIPS (IP varchar(50))')  # 创建表
        except Exception as e:
            pass

        for ip in CSubnetIPS:
            sql = "insert into CSubnetIPS values('{}')".format(ip)
            print(sql)
            cu.execute(sql)

        conn.commit()
        cu.close()
