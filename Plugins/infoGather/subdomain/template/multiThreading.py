# -*- coding:utf-8 -*-
# 多线程框架模板

from Wappalyzer import Wappalyzer, WebPage
from threading import Thread
import sys
from Queue import Queue
from traceback import print_exc
import warnings

warnings.filterwarnings('ignore')
import re
from sys import version_info
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

PY2, PY3 = (True, False) if version_info[0] == 2 else (False, True)
if PY2:
    from Queue import Queue
    from urlparse import urlparse
else:
    from queue import Queue
    from urllib.parse import urlparse


# 友链爬取
class webDetect:
    def __init__(self, Hosts, save_fold_path, fileName):
        self.Hosts = Hosts  # 域名或者IP
        self.save_fold_path = save_fold_path
        self.fileName = fileName

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.TIMEOUT = 10
        self.threadsNum = 100
        self.queueTasks = Queue(-1)  # 存放域名或IP的任务队列
        self.port = [21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 873, 993, 995, 1080, 1723, 1433, 1521,
                     3306, 3389, 3690, 5432, 5800, 5900, 6379, 7001, 81, 88, 89, 888, 880, 8000, 8001, 8080, 8081, 8888,
                     9200, 9300, 9080, 9999, 11211, 27017]
        self.allServerInfo = self.read_config('./scanPort/server_info.ini')  # 读取端口服务的正则表达式
        self.TIMEOUT = 10  # socket的延时
        self.port_info = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.title_patten = re.compile('<title>(.*)?</title>')

    def run(self):
        for host in self.Hosts:
            self.queueTasks.put(host)

        threads = []
        for i in range(1, self.threadsNum + 1):
            t = Thread(target=self.scan)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def scan(self):
        while not self.queueTasks.empty():
            queueTask = self.queueTasks.get()
            try:
                pass
            except Exception:
                pass

    def save(self, content):
        with open('{}/{}_ports.txt'.format(self.save_fold_path, self.fileName), 'at') as f:
            f.writelines('{}\n'.format(content))