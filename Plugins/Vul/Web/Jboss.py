import requests
import threading
from termcolor import cprint
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


class Detect(threading.Thread):
    name = 'Jboss'

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

    # 只需要修改下面的代码就行
    def run_detect(self, url):
        self.attack(url)

    def attack(self, url):
        self.CVE_2017_12149(url)
        self.unauth(url)


    # 控制台未授权
    def unauth(self, url):
        unauth_url = url + '/jmx-console/'
        try:
            res = requests.get(url=unauth_url, headers=self.headers, proxies=self.proxies, timeout=20)
            if res.status_code == 200 and 'Management Console' in res.text:     # 控制台未授权，可以部署war 拿shell
                tqdm.write(Fore.RED + '[Jboss unauth_url] {}'.format(unauth_url))
                self.vul_list.append(['Jboss', url, 'Yes unauth [{}]'.format(unauth_url)])
        except Exception as e:
            return False

    # JMXInvokerServlet 反序列化
    def CVE_2017_12149(self, url):
        jboss_url = url + '/invoker/JMXInvokerServlet'
        try:
            r = requests.get(url=jboss_url, headers=self.headers, proxies=self.proxies, timeout=20)
            # print(r.status_code)
            # print(r.url)
            # print(r.headers)
            if r.status_code == 200:
                if r.headers['content-type'].count('serialized') or r.headers['Content-Type'].count('serialized'):
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
    requests_proxies = None
    alive_Web_queue = Queue(-1)  # 将存活的web存入队列里
    for _ in alive_web:
        alive_Web_queue.put(_)

    threads = []
    thread_num = 100  # 漏洞检测的线程数目

    pbar = tqdm(total=alive_Web_queue.qsize(), desc="检测漏洞", ncols=150)  # total是总数

    for num in range(1, thread_num + 1):
        t = Detect(alive_Web_queue, pbar, vul_list, requests_proxies)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    tqdm.write(Fore.BLACK + '-'*50 + '结果' + '-'*50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))