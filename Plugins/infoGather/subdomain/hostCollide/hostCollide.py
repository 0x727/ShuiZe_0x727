'''
api：https://censys.io/api
文档：https://censys-python.readthedocs.io/en/stable/
例子：https://github.com/censys/censys-python/tree/main/examples
'''


import requests
import json
import time
import re
from threading import Thread
from queue import Queue
import threading
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import configparser
from tqdm import *
from colorama import Fore
import chardet

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
# cf.read("../../../../iniFile/config.ini") # 测试
secs = cf.sections()
UID = cf.get('censys api', 'UID')
SECRET = cf.get('censys api', 'SECRET')

TIMEOUT = 10
title_patten = re.compile('<title>(.*)?</title>', re.IGNORECASE)        # 忽略大小写

def getIP(result):
    temp_domainIPS = []
    for _ in result["results"]:
        temp_domainIPS.append(_['ip'])
    return temp_domainIPS


def censysApi(domain):
    censysIPS = []
    searchQuery = domain

    API_URL = "https://www.censys.io/api/v1"


    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

    dataFirstForPage = {
        "query": searchQuery,
        "page": 1,
        "fields": []
    }

    try:
        req = requests.post(API_URL + "/search/ipv4", data=json.dumps(dataFirstForPage), auth=(UID, SECRET), headers=headers, timeout=TIMEOUT)
        result = req.json()
        pages = int(result['metadata']['pages'])
        print("censys 结果页数 pages: {}".format(pages))
        censysIPS.extend(getIP(result))
        # 限制了查询页数，如果页数大于5页，则只取前5页。
        pages = 5 if pages > 5 else pages

        for page in range(2, pages + 1):
            print("req page{}".format(page))
            data = {"query": searchQuery, "page": page, "fields": ["ip"]}
            time.sleep(1)
            req = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET), headers=headers, timeout=TIMEOUT)
            result = req.json()
            censysIPS.extend(getIP(result))
    except Exception as e:
        pass

    censysIPS = list(set(censysIPS))
    return censysIPS



class Detect(threading.Thread):
    name = 'Host碰撞'

    def __init__(self, hostIPS_q, hostCollideResult):
        threading.Thread.__init__(self)
        self.hostIPS_q = hostIPS_q
        self.hostCollideResult = hostCollideResult


    def run(self):
        while not self.hostIPS_q.empty():
            host, ip = self.hostIPS_q.get()

            self.attack(host, ip)

            self.hostIPS_q.task_done()

    def get_title(self, res):
        cont = res.content
        # 获取网页的编码格式
        charset = chardet.detect(cont)['encoding']
        # 对各种编码情况进行判断
        html_doc = cont.decode(charset)
        title = re.search('<title>(.*)</title>', html_doc).group(1)
        return title

    def attack(self, host, ip):
        headers = {'Host': host,
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'}
        headers2 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'}
        urls = ["http://{}".format(ip), "https://{}".format(ip)]
        for url in urls:
            try:
                res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
                res2 = requests.get(url=url, headers=headers2, verify=False, timeout=TIMEOUT)
                title = self.get_title(res)
                title2 = self.get_title(res2)
                # 过滤直接访问IP也是正常响应，例如：host, ip = ["apitest.mobile.meituan.com", "47.108.170.229"]
                if res2.status_code != 200:
                    code = res.status_code
                    if code != 502 and code != 400:
                        print("[{}] {} {} {} {}".format(code, url, host, title, title2))
                        self.hostCollideResult.append([host, url, code, title, title2])
            except Exception as e:
                pass


# 判断是否是内网IP
def is_internal_ip(ip):
    ip_list = ip.split('.')
    if ip_list[0] == '10' or ip_list[0] == '127':
        return True
    elif ip_list[0] == '172' and 15 < int(ip_list[1]) < 32:
        return True
    elif ip_list[0] == '192' and ip_list[1] == '168':
        return True
    else:
        return False



# host碰撞
def run_hostCollide(domain, Subdomains_ips):
    hostCollideResult = []
    censysIPS = []
    allIps = []

    # 自域名解析的A记录是内网IP
    internal_ip_Subdomains = []
    for subdomain in Subdomains_ips.keys():
        ips = Subdomains_ips[subdomain]
        for ip in ips:
            if is_internal_ip(ip):
                internal_ip_Subdomains.append(subdomain)
            allIps.append(ip)

    print("共有{}个子域名的A记录是内网IP".format(len(internal_ip_Subdomains)))
    for _ in internal_ip_Subdomains:
        print(_)

    if len(internal_ip_Subdomains) != 0:
        censysIPS = censysApi(domain)
        print('cesys api : {} 共 {} 个解析出来的IP'.format(domain, len(censysIPS)))
        allIps.extend(censysIPS)
        allIps = list(set(allIps))
        print('共 {} 个IP'.format(len(allIps)))

        # 避免太多的子域名去碰撞
        if len(internal_ip_Subdomains) > 5:
            internal_ip_Subdomains = internal_ip_Subdomains[:5]

        hostIPS_q = Queue(-1)
        for ip in allIps:
            for host in internal_ip_Subdomains:
                hostIPS_q.put([host, ip])

        threads = []
        thread_num = 100  # 漏洞检测的线程数目

        for num in range(1, thread_num + 1):
            t = Detect(hostIPS_q, hostCollideResult)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        print("不碰撞Host")

    return hostCollideResult, censysIPS
