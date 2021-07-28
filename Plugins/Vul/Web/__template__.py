from termcolor import cprint
import requests
import threading
import re
import hashlib
from tqdm import *
from colorama import Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)



# 模板
class Detect(threading.Thread):
    name = '漏洞名'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue      # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

    def run(self):
        while not self.alive_Web_queue.empty():
            alive_web = self.alive_Web_queue.get()
            self.pbar.set_postfix(url=alive_web, vul=self.name)  # 进度条的显示
            self.run_detect(alive_web.rstrip('/'))
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.alive_Web_queue.task_done()

    # 调用各种漏洞检测方法
    def run_detect(self, url):
        # 检测是否是用友
        if self.check(url):
            # 漏洞1
            self.webVul1(url)

            # 漏洞2
            self.webVul2(url)

    def check(self, url):
        ico_url = url + '/logo/images/ufida.ico'
        m1 = hashlib.md5()
        try:
            m1.update(requests.get(url=ico_url, headers=self.headers, proxies=self.proxies, timeout=20, verify=False, allow_redirects=False).content)
            the_md5 = m1.hexdigest()
            # print(the_md5)
            if the_md5 == 'a5dccf6af79f420f7ea2f2becb6fafa5':
                tqdm.write(Fore.RED + '[{}] {}'.format('yongyou', url))
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
                    tqdm.write(Fore.RED + '[Jboss JMXInvokerServlet] {}'.format(url))
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
                    tqdm.write(Fore.RED + '[Jboss JMXInvokerServlet] {}'.format(url))
                    self.vul_list.append(['Jboss', url, 'Yes CVE-2017-12149'])
        except Exception as e:
            return False

if __name__ == '__main__':
    from queue import Queue

    alive_web = ['']
    vul_list = []
    # proxy = r''
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    # requests_proxies = {'http': '127.0.0.1:8080', 'https': '127.0.0.1:8080'}
    requests_proxies = None
    alive_Web_queue = Queue(-1)  # 将存活的web存入队列里
    for _ in alive_web:
        alive_Web_queue.put(_)

    threads = []
    thread_num = 1  # 漏洞检测的线程数目

    pbar = tqdm(total=alive_Web_queue.qsize(), desc="检测漏洞", ncols=150)  # total是总数

    for num in range(1, thread_num + 1):
        t = Detect(alive_Web_queue, pbar, vul_list, requests_proxies)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    pbar.close()            # 关闭进度条

    tqdm.write(Fore.BLACK + '-'*50 + '结果' + '-'*50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))