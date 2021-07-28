from termcolor import cprint
import requests
import threading
import re
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 邮箱-outlook，coremail
class Detect(threading.Thread):
    name = 'Email'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue  # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list  # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

    def run(self):
        while not self.alive_Web_queue.empty():
            alive_web = self.alive_Web_queue.get()
            self.pbar.set_postfix(url=alive_web, vul=self.name)  # 进度条的显示
            self.run_detect(alive_web.rstrip('/'))
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.alive_Web_queue.task_done()

    # 调用各种漏洞检测方法
    def run_detect(self, url):
        # outlook
        self.outlook(url)

        # coremail
        self.coremail(url)

    # outlook
    def outlook(self, url):
        outlook_url = url + '/owa/auth/logon.aspx'
        ews_url = url + '/ews'
        try:
            res = requests.get(url=outlook_url, headers=self.headers, proxies=self.proxies, verify=False, timeout=10)
            if res.status_code == 200 and 'Outlook Web App' in res.text:
                if requests.get(url=ews_url, headers=self.headers, proxies=self.proxies, verify=False, timeout=10).status_code == 401:
                    tqdm.write(Fore.RED + '[Outlook] {} ews!'.format(url))
                    self.vul_list.append(['Outlook', url, 'Yes ews'])
                else:
                    tqdm.write(Fore.RED + '[Outlook] {}'.format(url))
                    self.vul_list.append(['Outlook', url, 'Maybe'])
        except Exception as e:
            return False

    # coremail
    def coremail(self, url):
        coremail_url = url + '/coremail/common/index_cmxt50.jsp'
        try:
            res = requests.get(url=coremail_url, headers=self.headers, proxies=self.proxies, verify=False, timeout=10)
            if res.status_code == 200 and '/coremail/bundle/' in res.text:
                tqdm.write(Fore.RED + '[Coremail] {}'.format(url))
                self.vul_list.append(['Coremail', url, 'Maybe'])
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
    thread_num = 1  # 漏洞检测的线程数目

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