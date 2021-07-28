from termcolor import cprint
import requests
import threading
import re
import hashlib
from urllib.parse import urlparse

# 模板
class Detect(threading.Thread):
    name = '漏洞'

    def __init__(self, param_Links_queue, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.param_Links_queue = param_Links_queue      # 存活动态链接的队列
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

    def run(self):
        while not self.param_Links_queue.empty():
            param_link = self.param_Links_queue.get()
            self.run_detect(param_link.strip())

    # 调用各种漏洞检测方法
    def run_detect(self, url):
        url_parse = urlparse(url)
        query = url_parse.query


    def check(self, url):
        ico_url = url + '/logo/images/ufida.ico'
        m1 = hashlib.md5()
        try:
            m1.update(requests.get(url=ico_url, headers=self.headers, proxies=self.proxies, timeout=20, verify=False, allow_redirects=False).content)
            the_md5 = m1.hexdigest()
            # print(the_md5)
            if the_md5 == 'a5dccf6af79f420f7ea2f2becb6fafa5':
                cprint('[{}] {}'.format('yongyou', url), 'red')
                self.vul_list.append(['yongyou', url, 'Maybe'])
                return True
            else:
                return False
        except Exception as e:
            return False

    # 漏洞1
    def webVul1(self, url):
        jboss_url = url + '/invoker/JMXInvokerServlet'
        try:
            res = requests.get(url=jboss_url, headers=self.headers, proxies=self.proxies, verify=False, timeout=10)
            if res.status_code == 200:
                if res.headers['content-type'].count('serialized') or res.headers['Content-Type'].count('serialized'):
                    cprint('[Jboss JMXInvokerServlet] {}'.format(url), 'red')
                    self.vul_list.append(['Jboss', url, 'Yes CVE-2017-12149'])
        except Exception as e:
            return False

    # 漏洞2
    def webVul2(self, url):
        jboss_url = url + '/invoker/JMXInvokerServlet'
        try:
            res = requests.get(url=jboss_url, headers=self.headers, proxies=self.proxies, verify=False, timeout=10)
            if res.status_code == 200:
                if res.headers['content-type'].count('serialized') or res.headers['Content-Type'].count('serialized'):
                    cprint('[Jboss JMXInvokerServlet] {}'.format(url), 'red')
                    self.vul_list.append(['Jboss', url, 'Yes CVE-2017-12149'])
        except Exception as e:
            return False

if __name__ == '__main__':
    from queue import Queue

    param_Links = ['http://192.168.168.152/sqli/Less-1/?id=1&type=2', 'http://192.168.168.152/sqli/Less-8/?id=1']
    vul_list = []
    # proxy = r'45.248.84.157:65361'
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    requests_proxies = None
    param_Links_queue = Queue(-1)  # 将存活的动态链接存入队列里
    for _ in param_Links:
        param_Links_queue.put(_)

    threads = []
    thread_num = 1  # 漏洞检测的线程数目

    for num in range(1, thread_num + 1):
        t = Detect(param_Links_queue, vul_list, requests_proxies)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    print(vul_list)