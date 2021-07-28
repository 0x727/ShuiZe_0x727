import re
from sys import version_info
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from queue import Queue
from urllib.parse import urlparse
from threading import Thread

# 友链爬取
class FriendChins:
    def __init__(self, domain, temp_subdomains):
        self.domain = domain
        self.temp_subdomains = temp_subdomains
        # self.save_fold_path = save_fold_path
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.TIMEOUT = 10
        # 域名匹配规则
        self.domain_patten = re.compile('https?:\/\/[^"/]+?\.{}'.format(domain))
        self.emails_patten = re.compile(r'[\w]+@[\w.]*{}'.format(domain))
        self.new_subdomains = Queue(-1)     # 需要跑的子域名
        self.old_subdomains = []            # 已经跑过的子域名
        self.fcSubdomains = []
        self.threadsNum = 30

    def run(self):
        for _ in self.temp_subdomains:
            self.new_subdomains.put(_.strip())

        threads = []
        for t_id in range(self.threadsNum):
            t = Thread(target=self.start, args=(t_id, ))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return list(set(self.fcSubdomains))

    def start(self, t_id):
        while not self.new_subdomains.empty():
            new_subdomain = self.new_subdomains.get()
            print('[t_id: {}] [{}] curl : {}'.format(t_id, self.new_subdomains.qsize(), new_subdomain))
            self.req(new_subdomain)


    def req(self, new_subdomain):
        url = 'http://{}'.format(new_subdomain)
        try:
            res = requests.get(url=url, headers=self.headers, timeout=self.TIMEOUT, verify=False)
            output_content = '\t[{}] curl : [{}] {}'.format(self.new_subdomains.qsize(), res.status_code, new_subdomain)
            print(output_content)
        except Exception:
            # self.url_except.append(url)  # 将请求异常的url放入url_except列表里。
            return None

        try:
            self.old_subdomains.append(new_subdomain)
            FC_subdomains = list(set(re.findall(self.domain_patten, res.text)))  # 子域名列表,去重结果
            #emails = list(set(re.findall(self.emails_patten, res.text)))         # 邮箱列表,去重结果
            #print('[{}] {}'.format(new_subdomain, emails))
            # 遍历匹配到的所有子域名
            for FC_subdomain in FC_subdomains:
                FC_subdomain = urlparse(FC_subdomain).netloc
                # 如果这个子域名之前没有被爬过,不在一开始的子域名列表里，不在之前爬到的友链里，则添加到待爬的队列里
                if FC_subdomain not in self.old_subdomains and FC_subdomain not in self.temp_subdomains and FC_subdomain not in self.fcSubdomains:
                    output_content = '\t[+] : {}'.format(FC_subdomain)
                    print(output_content)
                    self.new_subdomains.put(FC_subdomain)
                    self.fcSubdomains.append(FC_subdomain)
        except Exception:
             pass

