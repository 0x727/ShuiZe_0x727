from termcolor import cprint
import requests
import threading
import re
from urllib.parse import urlparse
from threading import Thread
from queue import Queue
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 模板
class Detect(threading.Thread):
    name = 'back-up'

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
        # 备份文件
        self.backupFile(url)

    # 备份文件
    def backupFile(self, url):
        # 判断是否是IP
        def isIP(url):
            p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
            if p.match(url):
                return True
            else:
                return False

        # 检测
        def attack(backupFilesQueue):
            while not backupFilesQueue.empty():
                back_url = backupFilesQueue.get()
                try:
                    res = requests.get(url=back_url, headers=self.headers, proxies=self.proxies, allow_redirects=False, verify=False, timeout=10)
                    length = int(res.headers["Content-Length"])
                    # print('[{}] [{}] {}'.format(res.status_code, length, back_url))
                    if res.status_code == 200 and 'text/html' not in res.headers["Content-Type"] and 'text/plain' not in res.headers["Content-Type"] and 'application/json' not in res.headers["Content-Type"] and 'image/jpeg' not in res.headers["Content-Type"]:
                        tqdm.write(Fore.RED + '[Backup File] {} length: {}'.format(back_url, length))
                        self.vul_list.append(['Backup File', back_url, 'Yes Length:{}'.format(length)])
                except Exception as e:
                    # print(e)
                    pass

        if isIP(urlparse(url).netloc):
            subDomains = []
        else:
            subDomains = urlparse(url).netloc.split('.')[:-1]
        filePrefixs = list(set(["www", "wwwroot", "backup", "web"] + subDomains))
        # print(filePrefixs)
        fileSuffixs = ["zip", "rar", "tar.gz"]
        backupFilesQueue = Queue(-1)

        for filePrefix in filePrefixs:
            for fileSuffix in fileSuffixs:
                # print(filePrefix + '.' + fileSuffix)
                backupFilesQueue.put(url + '/' + filePrefix + '.' + fileSuffix)

        threads = []
        threadNum = 3
        for num in range(threadNum):
            t = Thread(target=attack, args=(backupFilesQueue, ))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()


if __name__ == '__main__':



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